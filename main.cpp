#include <cstdint>
#include <cstring>
#include <stdio.h>
#include <inttypes.h>
#include <string>
#include <fcntl.h>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <filesystem>

#ifdef _WIN32
#pragma comment(lib, "Ws2_32.lib")
#include <winsock2.h>
#include <ws2tcpip.h>

#define sleep(x) Sleep((x) * 1000)

#else
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <signal.h>
#endif

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <simdjson.h>

#ifdef __LITTLE_ENDIAN__
#define htonll(x) ((((uint64_t)htonl(x)) << 32) + htonl((x) >> 32))
#define ntohll(x) ((((uint64_t)ntohl(x)) << 32) + ntohl((x) >> 32))
#else
#define htonll(x) (x)
#define ntohll(x) (x)
#endif

#ifdef LOG
#define logprintf(...) printf(__VA_ARGS__)
#else
#define logprintf(...) ((void)0)
#endif

#define FRAME_FIN (1 << 7)
#define FRAME_UTF8 (1 << 0)

#ifdef _WIN32
#define CLOSE_SOCKET closesocket
#else
#define CLOSE_SOCKET close
#endif

#define RECONN(ssl, client, GOTO) \
  sleep(3);                       \
  SSL_free((ssl));                \
  CLOSE_SOCKET((client));         \
  goto GOTO;
#define RECONN2(ssl, client, GOTO) \
  SSL_free((ssl));                 \
  CLOSE_SOCKET((client));          \
  goto GOTO;

enum class MESSAGETYPE {
  SENDMESSAGE
};
struct MESSAGEFRAME {
  MESSAGETYPE type;
  std::string channelid;
  std::vector<uint8_t> content;
  std::string targetuserid;
};

constexpr unsigned BUFSIZE = 65536;
constexpr float JITTER = 0.7f;

enum class GATEWAY_EVENT_TYPE {
  UNNOWN = -1,
  READY = 0,
  HEARTBEAT = 1,
  HELLO = 10,
  HEARTBEAT_ACK = 11,
  RECONNECT = 7,
  INVALIDSESSION = 9,
};
GATEWAY_EVENT_TYPE op = GATEWAY_EVENT_TYPE::UNNOWN;
uint64_t heartbeat_interval;
bool sequenceisNull = true;
int64_t sequence;
std::mutex httplock;
std::condition_variable httpcv;
std::queue<MESSAGEFRAME *> messagequeue;

void ignore_sigpipe() {
#ifndef _WIN32
  struct sigaction act;
  int r;
  memset(&act, 0, sizeof(act));
  act.sa_handler = SIG_IGN;
  act.sa_flags = SA_RESTART;
  r = sigaction(SIGPIPE, &act, NULL);
#endif
}

int SSL_writeAll(SSL *ssl, const void *buf, int num) {
  int n = 0;
  while (n < num) {
    int res = SSL_write(ssl, (char *)buf + n, num - n);
    if (res <= 0) {
      const int code = SSL_get_error(ssl, res);
      switch (code) {
        case SSL_ERROR_WANT_READ:
          break;
        case SSL_ERROR_WANT_WRITE:
          break;
        default:
          fprintf(stderr, "SSL_write failed %d\n", code);
          return n;
      }
    } else
      n += res;
  }
  return n;
}
int SSL_readOnce(SSL *ssl, void *buf, int num) {
  memset(buf, 0, num);
REPEAT:;
  int red = SSL_read(ssl, buf, num);
  if (red <= 0) {
    const int code = SSL_get_error(ssl, red);
    switch (code) {
      case SSL_ERROR_WANT_READ:
        break;
      case SSL_ERROR_WANT_WRITE:
        break;
      default:
        fprintf(stderr, "SSL_read failed %d\n", code);
        return red;
    }
    goto REPEAT;
  }
  logprintf("read %d : %.*s\n", red, red, (const char *)buf);
  return red;
}

// https://datatracker.ietf.org/doc/html/rfc6455
int sendf(SSL *ssl, char *buf, uint64_t len, bool fin = true) {
  logprintf("sendf %d : %.*s\n", (int)len, (int)len, buf);
  static uint8_t obuf[BUFSIZE];
  uint8_t mask[4];
  unsigned framesize = 6;
  obuf[0] = (FRAME_UTF8 | (fin ? FRAME_FIN : 0));
  if (len <= 125) {
    obuf[1] = len | 0x80;  // 0x80는 MASK(on)
  } else if (len > 125 && len <= 0xffff) {
    framesize = 8;
    obuf[1] = 126 | 0x80;
    *((uint16_t *)(obuf + 2)) = htons(len);
  } else {
    framesize = 14;
    obuf[1] = 127 | 0x80;
    *((uint64_t *)(obuf + 2)) = htonll(len);
  }
  uint16_t q = *((uint16_t *)obuf + 1);
  unsigned mask_int = rand();
  memcpy(mask, &mask_int, 4);

  for (int i = 0; i < 4; i++) {
    obuf[(framesize - 4) + i] = mask[i];
  }
  for (int i = 0; i < len; i++) {
    obuf[framesize + i] = buf[i] ^ mask[i % 4];
  }
  return SSL_writeAll(ssl, obuf, framesize + len);
}
// op1
int sendheartbeat(SSL *ssl) {
  static char buf[128];
  memset(buf, 0, 128);
  if (sequenceisNull) {
    strcpy(buf, "{\"op\":1,\"d\":null}");
  } else {
    sprintf(buf, "{\"op\":1,\"d\":%" PRId64 "}", sequence);
  }
  return sendf(ssl, buf, strlen(buf));
}
// op2
int sendIdentify(SSL *ssl, const std::string &token) {
  static char buf[512];
  memset(buf, 0, sizeof(buf));
  sprintf(buf, "{\"op\":2,\"d\":{\"token\":\"%s\",\"intents\":%u,\"properties\":{\"os\": \"example\",\"browser\":\"example\",\"device\":\"example\"}}}", token.c_str(), 3276799);
  return sendf(ssl, buf, strlen(buf));
}
void getseq(simdjson::ondemand::document &doc) {
  if (doc["s"].get(sequence) == simdjson::SUCCESS) {
    sequenceisNull = false;
  }
}
// op6
int sendresume(SSL *ssl, const std::string &token, const std::string &sesid) {
  if (sesid == "") return -1;
  static char buf[512];
  memset(buf, 0, 512);
  if (sequenceisNull) {
    sprintf(buf, "{\"op\":6,\"d\":{\"token\":\"%s\",\"session_id\":\"%s\",\"seq\":null}}", token.data(), sesid.c_str());
  } else {
    sprintf(buf, "{\"op\":6,\"d\":{\"token\":\"%s\",\"session_id\":\"%s\",\"seq\":%" PRId64 "}}", token.data(), sesid.c_str(), sequence);
  }
  return sendf(ssl, buf, strlen(buf));
}

void httpthread(SSL_CTX *ctx, char *tokenc) {
  ignore_sigpipe();
  MESSAGEFRAME *frame = nullptr;
RECONNECT:;
  int client = socket(PF_INET, SOCK_STREAM, 0);

  char buf[BUFSIZE];
  struct addrinfo hints =
                      {
                          0,
                      },
                  *addr;
  int ret = getaddrinfo("discord.com", "443", &hints, &addr);
  if (ret != 0) {
    fprintf(stderr, "http getaddrinfo failed: %s\n", gai_strerror(ret));
    sleep(3);
    CLOSE_SOCKET(client);
    goto RECONNECT;
  }
  ret = connect(client, addr->ai_addr, addr->ai_addrlen);
  if (ret != 0) {
#ifdef _WIN32
    fprintf(stderr, "http Failed to connect to httpthread server: %d\n", WSAGetLastError());
#else
    fprintf(stderr, "http Failed to connect to httpthread server: %s\n", strerror(errno));
#endif
    sleep(3);
    CLOSE_SOCKET(client);
    goto RECONNECT;
  }
  SSL *ssl = SSL_new(ctx);
  if (!ssl) {
    fputs("http Failed to create SSL connection\n", stderr);
    abort();
  }
  SSL_set_fd(ssl, client);
  ret = SSL_connect(ssl);
  if (ret <= 0) {
    const int code = SSL_get_error(ssl, ret);
    fprintf(stderr, "http SSL_connect failed %d\n", code);
    RECONN(ssl, client, RECONNECT);
  }
  puts("http connected");
  
  while (true) {
    if(!frame) {
      std::unique_lock<std::mutex> uniqueLock(httplock);
      while (messagequeue.size() == 0) {
        httpcv.wait(uniqueLock);
      }
      frame = messagequeue.front();
      messagequeue.pop();
      uniqueLock.unlock();
    }
    memset(buf, 0, sizeof(buf));
    if (frame->type == MESSAGETYPE::SENDMESSAGE) {
      sprintf(buf,
              "POST /api/v10/channels/%s/messages HTTP/1.1\r\n"
              "Authorization: Bot %s\r\n"
              "User-Agent: DiscordBot (example, v0.1)\r\n"
              "Content-Length: %zu\r\n"
              "Connection: keep-alive\r\n"
              "Host: discord.com\r\n"
              "Content-Type: application/json\r\n\r\n"
              "{\"content\":\"%.*s\"}",
              frame->channelid.c_str(), tokenc, frame->content.size() + sizeof("{\"content\":\"\"}") - 1, (int)(frame->content.size()), (char *)frame->content.data());
    } else {
      delete frame;
      frame = nullptr;
      continue;
    }
    ret = SSL_write(ssl, buf, strlen(buf));
    if (ret <= 0) {
      const int code = SSL_get_error(ssl, ret);
      fprintf(stderr, "http SSL_write failed %d\n", code);
      break;
    } else {
      logprintf("write http %d : %.*s\n", ret, ret, buf);
    }
    ret = SSL_read(ssl, buf, strlen(buf));
    if (ret >= 1) {
      logprintf("read http %d : %.*s\n", ret, ret, buf);
      delete frame;
      frame = nullptr;
    } else {
      const int code = SSL_get_error(ssl, ret);
      fprintf(stderr, "http SSL_read failed %d\n", code);
      break;
    }
  }
  RECONN(ssl, client, RECONNECT);

  if(frame) {
    delete frame;
    frame = nullptr;
  }
  SSL_free(ssl);
  CLOSE_SOCKET(client);
}

void AddMessageQueue(MESSAGEFRAME *_messageFrame) {
  messagequeue.push(_messageFrame);
  httpcv.notify_one();
}

int main() {
  int ret;
#ifdef _WIN32
  WSADATA wsaData;
  ret = WSAStartup(MAKEWORD(2, 2), &wsaData);
  if (ret != 0) {
    fprintf(stderr, "WSAStartup failed: %d\n", ret);
    return -1;
  }
#endif
  srand(time(nullptr));
  ignore_sigpipe();

  // C++ 프로그램 작업 경로 바꾸기
#ifdef _WIN32
  char curPath[MAX_PATH];
  GetModuleFileName(nullptr, curPath, MAX_PATH);
#else
  char curPath[PATH_MAX];
  auto len = readlink("/proc/self/exe", curPath, PATH_MAX);
  curPath[len] = '\0';
#endif
  std::filesystem::current_path(std::filesystem::path(curPath).parent_path());

  simdjson::ondemand::parser parser;
  simdjson::ondemand::parser tokenparser;
  simdjson::ondemand::document doc;
  auto tokenjson = simdjson::padded_string::load("key/token.json");
  char redBuf[BUFSIZE];
  simdjson::ondemand::document tokendoc;
  tokendoc = tokenparser.iterate(tokenjson);
  auto tokenobj = tokendoc.get_object();
  std::string_view token;
  tokenobj["token"].get(token);
  char *tokenc = new char[token.size() + 1];
  tokenc[token.size()] = 0;
  memcpy(tokenc, token.data(), token.size());

  SSL *ssl;
  SSL_CTX *ctx;

  SSL_library_init();
  OpenSSL_add_all_algorithms();
  SSL_load_error_strings();
  ERR_load_crypto_strings();

  ctx = SSL_CTX_new(TLS_client_method());

  std::thread httpth(httpthread, ctx, tokenc);
  httpth.detach();

  std::string sesid;
  std::string gatewayurl = "gateway.discord.gg";

RECONNECT:;
  bool op2 = false;
  ssl = SSL_new(ctx);
  if (!ssl) {
    fputs("Failed to create SSL connection\n", stderr);
    return -1;
  }
  int client = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
  struct addrinfo hints =
                      {
                          0,
                      },
                  *addr;
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  ret = getaddrinfo(gatewayurl.c_str(), "443", &hints, &addr);
  if (ret != 0) {
    fprintf(stderr, "getaddrinfo failed: %s\n", gai_strerror(ret));
  newconnection:;
    if (gatewayurl != "gateway.discord.gg") {
      sequenceisNull = true;
      gatewayurl = "gateway.discord.gg";
    }
    RECONN(ssl, client, RECONNECT);
  }

  timeval timeout;
  ret = connect(client, addr->ai_addr, addr->ai_addrlen);
  if (ret != 0) {
#ifdef _WIN32
    const auto code = WSAGetLastError();
    fprintf(stderr, "Failed to connect to server: %d\n", code);
#else
    fprintf(stderr, "Failed to connect to server: %s\n", strerror(errno));
#endif
    goto newconnection;
  }
#ifdef _WIN32
  u_long arg = 1;
  if (ioctlsocket(client, FIONBIO, &arg) != 0) {
    fprintf(stderr, "ioctlsocket failed: %d\n", WSAGetLastError());
    return -1;
  }
#else
  if (fcntl(client, F_SETFL, O_NONBLOCK) == -1) {
    fprintf(stderr, "fcntl failed: %s\n", strerror(errno));
    return -1;
  }
#endif
  SSL_set_fd(ssl, client);
  while (true) {
    ret = SSL_connect(ssl);
    if (ret <= 0) {
      const int code = SSL_get_error(ssl, ret);
      switch (code) {
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:
        case SSL_ERROR_WANT_CONNECT:
          break;
        default:
          fprintf(stderr, "SSL_connect failed %d\n", code);
          goto newconnection;
      }
    } else
      break;
  }
  puts("connected");
  std::string upgradeWSS =
      std::string("GET wss://") + gatewayurl +
      "/?v=10&encoding=json HTTP/1.1\r\n"
      "Host: " +
      gatewayurl +
      "\r\n"
      "Upgrade: websocket\r\n"
      "Connection: Upgrade\r\n"
      "Sec-WebSocket-Key: x3JJHMbDL1EzLkh9GBhXDw==\r\n"
      "Sec-WebSocket-Protocol: chat\r\n"
      "Sec-WebSocket-Version: 13\r\n\r\n";
  if (SSL_writeAll(ssl, upgradeWSS.c_str(), upgradeWSS.size()) <= 0) goto resumefailednewconnection;
  if (SSL_readOnce(ssl, redBuf, BUFSIZE) <= 0) goto resumefailednewconnection;

  puts("websocket upgrade success");
  if (gatewayurl != "gateway.discord.gg") {
    if (sendresume(ssl, sesid, tokenc) <= 0) {
    resumefailednewconnection:;
      if (gatewayurl != "gateway.discord.gg") {
        puts("resume failed! new connection..");
        gatewayurl = "gateway.discord.gg";
        sequenceisNull = true;
      }
      RECONN(ssl, client, RECONNECT);
    } else {
      puts("resume");
    }
  }
  while (true) {
    fd_set retsd;
    FD_ZERO(&retsd);
    FD_SET(client, &retsd);
    if (heartbeat_interval > 0) {
      timeout.tv_sec = heartbeat_interval / 1000;  // timeout 매번 다시 설정필요
      timeout.tv_usec = (heartbeat_interval - (timeout.tv_sec * 1000)) * 1000;
      timeout.tv_sec *= JITTER;  // (heartbeat_interval * JITTER(0~1))
      timeout.tv_usec *= JITTER;
    } else
      timeout = {99, 0};
    auto fnum = select(client + 1, &retsd, nullptr, nullptr, &timeout);
    if (fnum == -1) {
#ifdef _WIN32
      const auto code = WSAGetLastError();
      fprintf(stderr, "Failed select: %d\n", code);
#else
      fprintf(stderr, "Failed select: %s\n", strerror(errno));
#endif
      puts("resume connecting...");
      RECONN2(ssl, client, RECONNECT);
    }
    if (fnum == 0 || (!FD_ISSET(client, &retsd))) {
      if (heartbeat_interval > 0) {
        if (sendheartbeat(ssl) <= 0) {
          puts("resume connecting...");
          RECONN2(ssl, client, RECONNECT);
        }
      }
      continue;
    }
    if (SSL_readOnce(ssl, redBuf, BUFSIZE) <= 0) {
      puts("resume connecting...");
      RECONN2(ssl, client, RECONNECT);
    }

    auto pos = strchr(redBuf, '{');
    if (pos) {
      if (parser.iterate(pos, BUFSIZE - (pos - redBuf)).get(doc) != simdjson::SUCCESS) continue;
      uint64_t op_;
      if (doc["op"].get(op_) != simdjson::SUCCESS) continue;
      op = (GATEWAY_EVENT_TYPE)op_;
      switch (op) {
        case GATEWAY_EVENT_TYPE::READY: {
          getseq(doc);
          std::string_view sv;
          if (doc["d"]["session_id"].get(sv) == simdjson::SUCCESS) {
            sesid = {sv.begin(), sv.end()};
            if (doc["d"]["resume_gateway_url"].get(sv) == simdjson::SUCCESS) {
              gatewayurl = {sv.begin() + sv.find("gateway"), sv.end()};  // cut "wss://"
            }
            puts("ready");
          }
          std::string_view content;
          if (doc["t"].get(sv) == simdjson::SUCCESS &&
              doc["d"]["content"].get(content) == simdjson::SUCCESS) {
            if (sv.compare("MESSAGE_CREATE") == 0) {
              if (content.compare("!ping") == 0) {
                std::string_view channelid;
                if (doc["d"]["channel_id"].get(channelid) == simdjson::SUCCESS) {
                  constexpr std::string_view pong = "pong!";
                  AddMessageQueue(new MESSAGEFRAME({MESSAGETYPE::SENDMESSAGE, {channelid.begin(), channelid.end()}, {pong.begin(), pong.end()}, ""}));
                }
              }
            }
          }
        } break;
        case GATEWAY_EVENT_TYPE::HEARTBEAT:
          break;
        case GATEWAY_EVENT_TYPE::HELLO:
          if (doc["d"]["heartbeat_interval"].get(heartbeat_interval) != simdjson::SUCCESS) {
            printf("HELLO Json Data doesn't have 'd/heartbeat_interval' data\n");
            continue;
          }
          logprintf("recived heartbeat_interval %" PRIu64 "\n", heartbeat_interval);
          getseq(doc);
          if (sendheartbeat(ssl) <= 0) {
            RECONN2(ssl, client, RECONNECT);
          }
          puts("hello");
          break;
        case GATEWAY_EVENT_TYPE::HEARTBEAT_ACK:
          getseq(doc);
          if (!op2) {
            op2 = true;
            if (gatewayurl == "gateway.discord.gg") {
              if (sendIdentify(ssl, tokenc) <= 0) {
                RECONN2(ssl, client, RECONNECT);
              }
            }
          }
          break;
        case GATEWAY_EVENT_TYPE::RECONNECT:
          puts("resume connecting...");
          puts("reconnect");
          RECONN2(ssl, client, RECONNECT);
        case GATEWAY_EVENT_TYPE::INVALIDSESSION:
          bool d;
          if (doc["d"].get(d) != simdjson::SUCCESS) {
            printf("INVALIDSESSION Json Data doesn't have 'd' data\n");
            d = false;
          }
          if (d) {
            puts("resume connecting...");
          } else {
            gatewayurl = "gateway.discord.gg";
            puts("new connecting...");
          }
          puts("invalid session");
          RECONN2(ssl, client, RECONNECT);
        default:
          printf("invaild 'op' %d\n", (int)op);
          continue;
      }
    }
  }
  SSL_free(ssl);
  CLOSE_SOCKET(client);
  delete[] tokenc;
#ifdef _WIN32
  WSACleanup();
#endif
  return 0;
}