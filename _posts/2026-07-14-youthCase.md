---
layout: single
title: 'Dreamhack Switching Command를 통해 배우는 PHP의 엄격한 일치 연산자'
sidebar:
    nav: "main"
tag : [dreamhack, web, 웹 해킹, exploit, nginx, express, nodejs]
categories: [wargame, 보안]
toc : true
toc_sticky: true
toc_label: "Contents"
author_profile: true
search: true
comments: true
published: true
---

<div class="notice--success">  
본 포스팅은 드림핵의 가이드라인을 준수하여 작성되었습니다. 전체 익스플로잇 스크립트나 FLAG 값은 포함하지 않으며, 취약점의 원리 분석과 방어 대책에 집중합니다.
</div>

안녕하세요! 오늘은 드림핵(Dreamhack)의 **youth-Case** 워게임 문제를 풀어보며 "Nginx"라는 웹 서버와 "Express(Node.js)"라는 백엔드 서버가 특정 문자들을 해석하고 처리하는 방식 서로 달라 발생하는 파싱 차이(Parsing Discrepancy) 취약점에 대해 공부한 과정을 소개 하려고 합니다.<br>

문제를 풀기 전, 제가 스스로 취약점을 분석하고 공격 로직을 세우기 위해 디딤돌로 삼았던 드림핵 공식 학습 링크와 챌린지 주소를 아래에 공유합니다.<br>

### 🔗 주요 관련 링크 바로가기
{: .no_toc}

| 구분 | 링크 안내 |
| :--- | :--- |

| **워게임 도전** | [<🎯 드림핵 공식 Switching Command 워게임 챌린지 링크>](https://dreamhack.io/wargame/challenges/1402){: .btn .btn--danger} |

---

이 문제의 핵심은 **"앞단(Nginx)의 필터링은 피하면서, 뒷단(Express)의 라우터에는 정상적으로 도달하게 만드는 것"**입니다.

## 1. 코드 분석

### (1) app.js
{: .no_toc}

```js
const express = require("express")
app.use(express.urlencoded({ extended: true }))

///words 배열 내의 name 값도 대문자여야 하며 null 값이 존재하면 안됩니다.
///즉 배열이면서 대문자 
function search(words, leg) {
    return words.find(word => word.name === leg.toUpperCase())
}

/*post 메소드 사용 */
app.post("/shop",(req, res)=>{
    // 사용자가 보낸 POST 바디 데이터에서 leg를 가져와 소문자로 변환
    const leg = req.body.leg.toLowerCase()

//만약 입력값이 'flag'라면 접근을 거부 / 우회해야 하는 필터링 ==> 배열 형태로 입력하여 우회 가능
    if (leg == 'flag'){
        return res.status(403).send("Access Denied")
    }
// 3. 필터링을 통과하면 search 함수를 통해 words 객체에서 leg를 검색
    const obj = search(words,leg)
    ///즉 FLAG대문자로 검색을 해야 다음 단계 가능

// 4. 검색 결과(obj)가 존재하면 결과를 JSON 문자열로 반환
    if (obj){
        return res.send(JSON.stringify(obj))
    }

    return res.status(404).send("Nothing")
})
```

Express 백엔드에서는 `/shop` 경로로 들어오는 `POST ` 요청을 처리합니다.
내부적으로는 leg 파라미터에 대해 소문자 젼환(`toLowerCase()`) 후 flag 문자열 검증을 수행하고 있습니다.

하지만 자바스크립트 엔진 특유의 **유니코드 합자** 처리 방식과 대소문자 변환 로직의 허점을 이용하면 우회 가능 합니다!


### (2) nginx.conf(Nginx 웹 서버)
{: .no_toc}

```conf
http {
    server {
        listen 80;
        listen [::]:80;
        server_name  _;

        # /shop경로는 거부당함
        location = /shop {
            deny all;
        }
# /shop/우회 경로 또한 거부 당함
        location = /shop/ {
            deny all;
        }
#차단 경로를 피해간 나머지 모든 요청은 Express 백엔드(http://app:3000/)로 전달
#이때  `/`를 제외한 나머지 경로 전체를 보냄
#즉 위 두개의 차단망을 피하고 왔을때 /shop이 되게 만들어야 함
# ==> //shop? ==>requests 모듈 자동 인코딩으로 안됨
#URL을 정규화(Normalization)하여 중복 슬래시를 전부 합친 뒤 백엔드로 전달
        location / {
            proxy_pass http://app:3000/;
        }

    }

}
```
Nginx 설정 파일을 보면 location = /shop과 location =/shop/ 구조를 통해 해당 경로로 들어오는 요청을 강력하게 차단하고 있습니다.<br>

이러한 Nginx의 차단망을 피해서 백엔드의 /shop 라우터에 패킷을 안착시키려면, Nginx는 다른 주소로 인식 하되 Express는 같은 주소로 인식하는 특수문자를 찾아야 합니다!<br>

## 2. 취약점 발생 원리(Parsing Discrepancy)

이 취약점은 서로 다른 언어와 환경으로 빌드된 두 서버가 문자열을 바라보는 <font color='#fc2e2e'>기준</font>의 차이에서 발생합니다.

처음 소스코드를 보았을 때 가장 큰 난관은 **"Nginx의 `= /shop` 차단막을 깨면서도, Express가 `/shop`으로 인식하게 만드는 문자가 무엇인가?"**와 **"Nginx의 `flag` 문자열 검사를 피하면서 Express 내부에서 `FLAG`로 바뀔 문자가 무엇인가?"**였습니다.<br>

이 실마리를 찾기 위해 유명한 웹 치트시트 사이트인 [HackTricks (Proxy/WAF Protections Bypass)](https://hacktricks.wiki/en/pentesting-web/proxy-waf-protections-bypass.html) 문서를 분석했고, 다음과 같은 힌트를 얻어 페이로드를 조립할 수 있었습니다.<br>

### (1) 주소창 해석 차이 (/shop\xa0)
{: .no_toc}
HackTricks의 Proxy 우회 아티클을 보면, 웹 서버와 백엔드 엔진이 **'공백'**을 처리하는 기준이 다를 때 발생하는 취약점들이 기술되어 있습니다.<br>

Nginx(C언어 기반): 매우 엄격하고 기계적으로 주소를 검사합니다.<br>
`=/shop` 설정은 토씨 하나 틀리지 않고 일치할 때만 막으므로, 뒤에 특수 공백이 붙은 `/shop\xa0` 요청이 들어오면 일치하지 않으므로 통과하게 됩니다.<br>

Express(자바스크립트 기반): 들어온 주소를 매칭할 때 , 맨 뒤에 붙은 특수 공백 문자인 `\xa0`을 불필요한 공백으로 판단하여 내부적으로 잘라내는 (Trim) 메커니즘이 작동합니다.<br>
즉, Nginx는 속이고 Express에서는 잘라내어 들어온 주소는 최종적으로 `/shop` 라우터와 매칭 됩니다!<br>


### (2) 본문 문자열 해석의 차이 (ﬂag)
{: .no_toc}

Nginx: 본문 내용에 flag라는 단어가 포함되어 있는지 검사할 때 바이트 단위로 단순 비교합니다.<br>
제가 유니코드 합자인 `ﬂ(\xef\xac\x82)` 문자를 섞어 `ﬂag`로 보내면, 일반 알파벳 `fl`과 다르게 인지하여 차단하지 않습니다<br>

Express: 자바스크립트에서는 내장 문자열 함수(`toLowerCase, to UpperCase`)등을 처리할 때 유니코드 정규화를 거치게 됩니다.<br>
이 과정에서 합자 기호인 `fl`문자가 일반 알파벳 `f`와 `l` 두 글자로 분리되면서, 조건문을 지날 때는 필터링을 피하고 최종 검색 단계에서는 정상적인 FLAG로 치환되어 데이터가 출력됩니다.<br>


## 3. 가설 설정 및 익스플로잇 설계

분석한 파싱 차이 취약점을 바탕으로, 시스템을 관통할 두 가지 핵심 공격 가설을 수립했습니다.<br>

1. **Nginx 방어선 우회 가설:** URL 경로 맨 뒤에 HTTP 표준 인코딩을 타지 않는 특수 공백 문자(`\xa0`)를 붙여 전송하면, Nginx의 경로 차단 목록을 회피한 채 Express 백엔드의 `/shop` 라우터에 안착할 것이다.<br>

2. **백엔드 필터링 우회 가설:** POST Body의 데이터로 일반 문자열 대신 유니코드 합자가 포함된 `ﬂag`를 전송하면, 백엔드의 소문자 검증 루틴을 무력화한 뒤 최종 대문자 변환 로직에서 정상적인 `FLAG` 데이터로 복원되어 원하는 값을 반환할 것이다.<br>

이 가설을 증명하기 위해, 자동 인코딩 기능이 주소창을 멋대로 가공하는 일반 라이브러리 대신, 패킷의 바이트 하나하나를 날것 그대로 제어할 수 있는 익스플로잇 스크립트를 구성하여 공격을 진행했습니다.<br>

## 4. requests / urllib3 라이브러리를 버리고 순수 socket을 선택한 이유

익스플로잇 스크립트를 작성할 때 제가 가장 먼저 고려하는 것은 범용적인 `requests` 모듈입니다.<br> 
하지만 이 문제에서 `requests`를 사용하면 주소창에 심어놓은 특수 공백 문자(`/shop\xa0`)가 서버로 출발하기 전에 **`/shop%C2%A0`**로 강제 자동 인코딩(Percent Encoding)되는 문제가 발생합니다.<br>

<div style="text-align: center; margin: 20px 0;">
  <img src="{{ '/images/youth-Case/requests' | relative_url }}" 
       alt="requests 자동 인코딩 과정" 
       style="max-width: 80%; height: auto; border: 1px solid #ddd; border-radius: 5px;">
  <p style="font-size: 0.9em; color: #666;">[requests 라이브러리의 자동 URL 정규화 및 인코딩 장벽]</p>
</div>

### (1) 어댑터 해킹도, urllib3.connectionpool도 전부 실패한 이유
이 장벽을 넘기 위해 `requests` 내부의 `HTTPAdapter`를 상속받아 발송 직전에 주소를 강제로 바꿔치기(`BurpAdapter`)해보기도 하고, `requests`를 배제한 채 그 하단 엔진인 `urllib3.connectionpool`을 꺼내어 직접 요청을 날려보기도 했습니다.<br>

파이썬 문법 에러를 고쳐가며 끝까지 밀어붙였으나 **결과는 전부 실패**였습니다.<br>

파이썬의 HTTP 통신 계열 라이브러리들은 내부적으로 주소창(URI) 문자열을 파싱하고 소켓 레이어로 넘겨줄 때, 웹 표준(RFC 규격)을 강제로 준수하도록 설계되어 있습니다.<br> 
제가 아무리 중간 단계에서 날것의 `\xa0` 문자를 주입해도, **결국 주소가 물리적인 패킷으로 변환되어 인터넷 선으로 나가기 바로 직전 최하단 필터링 구역에서 또다시 `%C2%A0`로 자동 복원**을 해버리기 때문입니다.<br>

결국 이 이중, 삼중의 자동 인코딩 감옥 때문에 백엔드(Express)는 이를 공백으로 인식하지 못하고 **`Cannot POST /shop%C2%A0` (404 Not Found)** 에러만을 저는 계속 불 수 밖에 없었습니다.<brs>

### (2) 유일한 돌파구: 어떤 참견도 없는 순수 `socket`
이 철통같은 "라이브러리의 참견과 자동 치유 본능"을 깨부수는 유일한 열쇠는 바로 파이썬 내장 **`socket` 모듈**이었습니다.

* **완벽한 통제권:** `socket`은 HTTP 규격이나 URL 표준 따위는 신경 쓰지 않는 가장 날것의 로우 레벨 통신 도구입니다.<br>
* **조작 패킷 직송:** HTTP 요청 헤더 문자열부터 시작해 우리가 원하는 타겟 경로인 `/shop\xa0` 바이트, 그리고 본문의 `leg=ﬂag` 바이트까지 **글자 하나하나를 내 손으로 직접 조립해서 선로에 곧바로 던져버립니다.**<br>

즉, 파이썬 라이브러리가 개입하여 패킷을 "안전하게 정화"할 기회를 완전히 박탈해 버리는 것입니다. <br>

결국 해킹(취약점 공격)을 위해 **'의도적으로 표준을 위반한 패킷'**을 전송해야 하는 워게임 환경에서는, 개발자 편의를 위해 과도하게 친절한 상위 라이브러리들이 오히려 거대한 장애물이 될 수 있으며, 데이터 전송의 전권을 쥘 수 있는 **순수 소켓 통신**만이 정답이 된다는 값진 교훈을 얻을 수 있었습니다.<br>

## 덧붙이며: requests 모듈 능력자 분들을 찾습니다!

사실 저는 이번 문제를 풀면서 `requests` 라이브러리로 스크립트를 작성하는 것에 완벽히 꽂혀서, 어댑터를 오버라이딩하고 내부 소스코드까지 까보며 수많은 삽질을 거쳤습니다. 

하지만 결과는 앞서 보신 것처럼 라이브러리 내부의 완고한 자동 인코딩 장벽에 막혀 실패로 끝났고, 결국 소켓으로 선회하여 문제를 해결했습니다. 

혹시 제가 놓친 기상천외한 방법이나 훅(Hook) 기능을 활용해, **순수 `requests` 모듈(또는 껍데기 레이어)을 유지한 채 이 `\xa0` 인코딩 장벽을 뚫고 문제를 해결하신 분**이 계신다면 제발 댓글로 지혜를 나눠주세요! 능력자분들의 달콤한 힌트와 피드백을 간절히 기다리고 있겠습니다.