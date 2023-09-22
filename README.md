# DiscordBot Example C++

C++언어로 웹 소켓을 이용해 디스코드 봇 간단 연결을 구현한 예제입니다. Windows, Linux 등 지원

이 프로그램을 빌드하려면 다음 라이브러리가 필요합니다.

- OpenSSL
- simdjson([https://github.com/simdjson/simdjson](https://github.com/simdjson/simdjson)) - 프로젝트에서 자동으로 설치됩니다.

그리고 디스코드 봇을 구동하려면 봇 토큰이 필요하고 프로그램 실행시 요구합니다. 프로그램과 같은 폴더에 "key" 폴더 추가 및 그 안에 다음과 같이 "token.json" 파일을 작성해주면 됩니다.

```json
{
    "token" : "<디스코드 봇 토큰>"
}
```

웹소켓 학습을 위해 작성된 예제이므로 제공되는 기능은 "ping!"을 입력했을 때 "pong!"으로 응답 정도 밖에 없습니다. [디스코드 게이트웨이](https://discord.com/developers/docs/topics/gateway) 및 [웹소켓](https://datatracker.ietf.org/doc/html/rfc6455) 스펙에 맞추어 충실하게 구현하도록 노력했지만 안정성을 보증할 수 없으므로 참고용으로만 사용해주세요.ㅠ 도움이 됐으면 좋겠습니다.😁

// 코드 설명 또는 주석은 시간이 되면..
