---
layout: single
title: 'Dreamhack NoSQL-CouchDB : nono패키지의 위험성'
sidebar:
    nav: "main"
tag : [dreamhack, web, 웹 해킹, exploit, NoSQL, CouchDB]
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

안녕하세요! 오늘은 드림핵(Dreamhack)의 **CouchDB** 워게임 문제를 풀어보며, 웹 환경에서 다소 생소할 수 있는 NoSQL 데이터베이스의 구조적 특징과 인증 우회 취약점을 다루어 보려고 합니다.

문제를 풀기 전, 제가 스스로 취약점을 분석하고 공격 로직을 세우기 위해 디딤돌로 삼았던 드림핵 공식 학습 링크와 챌린지 주소를 아래에 공유합니다.

---

##  학습을 위한 추천 로드맵 안내

CouchDB와 같은 특수한 NoSQL 취약점은 사전 지식 없이 접근하면 막막할 수 있습니다.<br>
 관련 내용을 처음 접하신다면 아래의 순서대로 학습을 먼저 진행해 보시는 것을 강력히 추천해 드립니다.

<div class="notice--info">
💡 <b>추천 팁!</b><br>
드림핵 공식 강의 끝부분에는 사실 '함께 실습하기'라는 정답 해설이 포함되어 있습니다. 하지만 저는 강의 본문만 정독한 뒤, <b>해설을 절대 보지 않고 홀로 워게임 챌린지에 맨땅에 헤딩하듯 부딪혀 보시는 것을 제안합니다.</b> 저 역시 CouchDB를 완벽히 알지 못하는 상태에서 공부해가며 스스로 해결해 냈기 때문에, 여러분도 정답지 없이 충분히 문제를 풀어내는 짜릿한 성취감을 맛보실 수 있을 것입니다!
</div>

### 🔗 주요 관련 링크 바로가기

| 구분 | 링크 안내 |
| :--- | :--- |
| **선행 학습** | [<📄 드림핵 공식 CouchDB 기본 개념 학습 링크>](https://learn.dreamhack.io/293){: .btn .btn--info} |
| **워게임 도전** | [<🎯 드림핵 공식 CouchDB 워게임 챌린지 링크>](https://dreamhack.io/wargame/challenges/419){: .btn .btn--danger} |

---

## 1. CouchDB 기본 지식 빠르게 살펴보기

CouchDB 문제를 풀기 위해 백엔드 코드와 패키지를 분석할 때, 반드시 알고 있어야 하는 **4가지 핵심 메커니즘**입니다.

---

###  1. 데이터 구조 및 통신 아키텍처
{: .no_toc}

* **Document 기반 저장소**: 데이터가 관계형(SQL) 테이블이 아닌, **키(Key)와 값(Value)이 한 쌍을 이루는 JSON 객체 형태의 도큐먼트**로 저장됩니다.

* **HTTP 기반 API 웹 서버**: CouchDB는 그 자체로 하나의 HTTP 서버처럼 동작합니다.<br>
즉, 데이터베이스의 모든 조회, 삽입, 삭제 요청을 웹 통신 메서드(`GET`, `POST`, `PUT`, `DELETE`)를 통해 처리합니다.

---

###  2. CouchDB만의 특수 구성 요소 (Special Endpoints)
{: .no_toc}

CouchDB는 URL 경로 및 JSON 필드 중에서 **언더바(`_`) 문자로 시작하는 요소**들을 내부 제어용 특수 구성 요소(API 엔드포인트)로 사용합니다.<br> 
이 규칙을 활용해 데이터베이스 전체를 조망할 수 있습니다.

| 특수 구성 요소 | 분류 | 주요 역할 및 반환 데이터 |
| :--- | :--- | :--- |
| **`/_all_dbs`** | **Server** 레벨 | CouchDB 인스턴스에 존재하는 **모든 데이터베이스 목록**을 반환 |
| **`/{db}/_all_docs`** | **Database** 레벨 | 지정한 데이터베이스(`{db}`)에 포함된 **모든 도큐먼트(내용물)**를 반환 |

> 💡 더 자세한 내장 특수 API 구조는 [드림핵 CouchDB 공식 강의](https://learn.dreamhack.io/293#2){: target="_blank"}를 참고하시면 좋습니다.

---

###  3. Node.js `nano` 패키지 분석 및 공격 벡터 판별
{: .no_toc}

Node.js 환경에서 CouchDB와 연동할 때 주로 사용하는 클라이언트 라이브러리가 바로 **`nano`** 패키지입니다.<br>
이 패키지는 데이터를 가져올 때 크게 두 가지 함수를 사용합니다.

```javascript
// 1. get() 함수 예시
db.get(docname, [params], [callback]);

// 2. find() 함수 예시
db.find(selector, [callback]);

```

💡 두 함수의 보안 성격 차이와 이번 문제의 핵심<br>


**find() 함수 (쿼리 기반)**: 객체 타입의 조건 연산자($gt, $regex 등)를 입력받을 수 있어, 입력값 필터링이 미흡할 경우 개발자가 의도하지 않은 NoSQL 인젝션(**객체 주입 공격**)을 수행할 수 있습니다.

**get() 함수 (_id 기반 조회)**: 인자로 전달된 고유 ID 값(docname)을 기반으로 타깃을 명확히 집어서 조회합니다.

<font color='#ff4032'>이번 문제의 공격 방향성</font>: 이번 CouchDB 문제는 연산자 조작이 가능한 find가 아닌 get 함수를 사용합니다.<br>

따라서 연산자를 이용한 인젝션 우회는 불가능하지만, docname 인자 자리에 `_all_docs`나 `_all_dbs` 같은 CouchDB 특수 엔드포인트 문자열이 필터링 없이 그대로 삽입될 경우, 단일 도큐먼트가 아닌 데이터베이스 전체 정보가 해커에게 노출되는 치명적인 취약점이 발생하게 됩니다!


## 2. 문제 핵심 소스코드 분석

**nono패키지 활용**

```java
const nano = require('nano')(`http://${process.env.COUCHDB_USER}:${process.env.COUCHDB_PASSWORD}@couchdb:5984`); 
```

위 소스코드를 통해 `nono` 패키지를 사용하고 있는 것을 알 수 있습니다.

**취약점 확인**

```java
app.get('/', function(req, res, next) {
  res.render('index');
});
/* POST auth 
get인자를 사용한 것으로 보아 _all_docs`, `_db` 활용 가능한지 확인*/
app.post('/auth', function(req, res) { /*auth 페이지에서 사용자의 입력 값을 get함의 인자값으로 사용*/
    users.get(req.body.uid, function(err, result) {
        if (err) {
            console.log(err);
            res.send('error');
            return;
        }
        if (result.upw === req.body.upw) { /*   /auth경로에서 req의 비번과 result의 비번이 같으면 flag 출력 */
            res.send(`FLAG: ${process.env.FLAG}`);
        } else {
            res.send('fail');
        }
    });
});
```

위 소스코드를 분석하면 다음과 같습니다.<br>
이용자의 입력 값을 `get함수`의 인자로 사용하는데 아무런 검사를 하지 않는다.<br>
=> 즉, `_all_docs` 페이지에 접근 가능!<br>
=> 이때 `/auth` 페이지에서 실행 해야 한다.<br>


## 3. 익스플로잇 페이로드 작성 가이드 (Payload Construction)

드림핵의 보안 가이드라인에 따라, 본 포스팅에서는 정답 플래그(FLAG)를 단번에 도출하는 완성형 익스플로잇 스크립트는 공개하지 않습니다. <br>

대신 앞서 분석한 **`nano.get()` 함수의 취약점(CouchDB 특수 구성 요소 접근)**을 공략하기 위해, 제가 수많은 시행착오 끝에 정립한 **두 가지 공격 무기의 뼈대(Framework)**를 공유합니다.<br> 

이 힌트들을 조합하여 직접 정답을 커스터마이징해 보시길 바랍니다!

---

### 1. Python `requests` 스크립트 활용 기법
{: .no_toc}

자동화 스크립트를 작성하거나 다량의 JSON 데이터를 정교하게 핸들링하고 싶을 때 가장 추천하는 파이썬 requests 라이브러리의 표준 기본 틀입니다.

```python
import requests

url = 'https://httpbin.org/post'
json_data = {'key': 'value'}

response = requests.post(url, json=json_data)

print(response.text)
```
**힌트** :이 틀을 기반으로 문제가 요구하는 JSON 데이터 구조와 변수명을 맞춰 매핑을 하면 재밌을 것 같습니다. 

### 2. Linux curl 터미널 명령어 활용 기법
{: .no_toc}

파이썬 스크립트를 짜지 않고도, 터미널(Terminal) 환경이나 Command Injection 공격 연계 시 가장 빠르고 강력하게 HTTP 요청을 변조하여 쏠 수 있는 curl 명령어 뼈대입니다.

```bash
curl -X POST  
-H  
-d 
```
**활용했던 주요 옵션 완벽 요약**
**-X**: 요청 시 사용할 HTTP 메소드(여기서는 POST)를 명시적으로 지정합니다.

**-H**: 전송할 HTTP 헤더를 지정합니다.<br> 
이 문제에서는 백엔드 서버가 우리가 던지는 데이터를 올바른 JSON 객체로 파싱할 수 있도록 내부적으로 Content-Type을 선언해 줄 때 유용하게 쓰입니다.

**-d**: HTTP Body에 실어 보낼 실질적인 데이터(Payload)를 기재합니다.

**결정적 힌트**:  저는 위 3가지 옵션을 전부 다 결합하여 익스플로잇에 성공했습니다.<br> 
NoSQL은 전달되는 데이터의 '**타입(Type)**'과 '**특수 구성 요소**'를 매우 민감하게 따진다는 점을 명심하고 옵션을 구성해 보시면 정말 재미있는 결과(응답값)를 확인하실 수 있을 것입니다!

<div style="text-align: center; margin: 20px 0;">
  <img src="{{ '/images/NoSQL_CouchDB/flag.png' | relative_url }}" 
       alt="flag 희득 완료" 
       style="max-width: 80%; height: auto; border: 1px solid #ddd; border-radius: 5px;">
  <p style="font-size: 0.9em; color: #f9f5f5;">[flag 희득 완료]</p>
</div>


## 4. 시큐어 코딩 

### 기존 app.js 소스코드 로직 수정
{: .no_toc}
```java
app.post('/auth', function(req, res) {
    const uid = req.body.uid;
    const upw = req.body.upw;
    //uid와 upw에 오직 문자열만 들어올 수 있도록 하여 객체나 배열 우회를 막았습니다!

    if (!uid || !upw || typeof uid !== 'string' || typeof upw !== 'string') {
        return res.send('fail');
    }
    //uid 완전 일치 검증하는 로직입니다!
     const query = {
        selector: {
            _id: { "$eq": uid } // $eq 연산자로 완전 일치(Exact Match) 검증
        },
        limit: 1
    };

    users.find(query, function(err, response) {
        if (err) {
            console.log(err);
            res.send('error');
            return;
        }

        // 3. 결과 확인: 문서가 존재하고 비밀번호가 일치하는지 검증합니다.
        if (response.docs && response.docs.length > 0) {
            const userDoc = response.docs[0];
            
            if (userDoc.upw === upw) {
                res.send(`FLAG: ${process.env.FLAG}`);
            } else {
                res.send('fail');
            }
        } else {
            res.send('fail');
        }
    });
});

```

<div style="text-align: center; margin: 20px 0;">
  <img src="{{ '/images/NoSQL_CouchDB/fail.png' | relative_url }}"
       alt="보안 성공!"
       style="max-width: 80%; height: auto; border: 1px solid #ddd; border-radius: 5px;">
  <p style="font-size: 0.9em; color: #ffffff;">[보안 성공]</p>
</div>



## 마치며

이번 문제를 해결하면서 지난번에 학습했던 **SimpleNote Manager** 문제의 핵심 키워드였던 `\`(역슬래시)의 기능을 다시 한번 활용해 볼 수 있어 매우 뜻깊었습니다.<br> 이전에 배운 취약점 포인트를 새로운 환경에 적용하며 시야를 넓힐 수 있었던 좋은 계기였습니다.<br>

또한, 관계형 데이터베이스(RDB)와는 다른 **CouchDB만의 독특한 특성과 개념**을 이해할 수 있었고, Node.js 환경에서 CouchDB를 제어하는 **`nano` 패키지**의 동작 방식과 라이브러리 레벨에서의 검증 한계에 대해 깊이 있게 학습할 수 있었던 유익한 문제였습니다.<br>

[<📄 드림핵 SimpleNote Manager 문제 링크>](https://dreamhack.io/wargame/challenges/1751){: .btn .btn--info}