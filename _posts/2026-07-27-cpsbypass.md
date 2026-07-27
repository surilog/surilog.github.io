---
layout: single
title: 'Dreamhack CSP Bypass를 통해 공부하는 콘텐츠 보안 정책'
sidebar:
    nav: "main"
tag : [dreamhack, web, 웹 해킹, exploit, xss, csp, src]
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

안녕하세요! 오늘은 드림핵(Dreamhack)의 **CSP Bypass** 워게임 문제를 풀어보며 콘텐츠 보안 정책에 대해 공부해보려고 합니다.<br>


문제를 풀기 전, 제가 스스로 취약점을 분석하고 공격 로직을 세우기 위해 디딤돌로 삼았던 드림핵 공식 학습 링크와 챌린지 주소를 아래에 공유합니다.<br>

## 🔗 주요 관련 링크 바로가기

| 구분 | 링크 안내 |
| :--- | :--- |
| **워게임 도전** | [🎯 드림핵 공식 CSP Bypass 워게임 챌린지 링크](https://dreamhack.io/wargame/challenges/435) |
| **관련 강의** | [🎯 드림핵 공식 CSP 강의 링크](https://learn.dreamhack.io/321) |

이 문제의 핵심은 CSP의 인라인 코드 보안 정책을 뚫고 스크립트를 실행하는 것입니다.<br>

## 1. 코드 분석


**@app.after_request**
```python
@app.after_request
def add_header(response):
    global nonce
    response.headers[
        "Content-Security-Policy"
    ] = f"default-src 'self'; img-src https://dreamhack.io; style-src 'self' 'unsafe-inline'; script-src 'self' 'nonce-{nonce}'"
    nonce = os.urandom(16).hex()
    return response


```
**app.after_request** 메소드의 **add_header(response)** 함수를 살펴보겠습니다.

함수는 response응답을 가지고 다음과 같은 CSP(콘텐츠 보안 정책)정책을 수행하고 있습니다.

| 구분 | 역할 |
| :--- | :--- |
| global nonce | 먼저 nonce 속성을 필요로 하고 있습니다. |
| default-src 'self'| -src로 끝나는 것은 같은 페이지에서 로드하는 것만 허용하고 있습니다. |
| img-src https://dreamhack.io | img 로드는 https://dreamhack.io에서만 가능합니다. |
| style-src 'self' | 스타일 시트 관련 출처 권한과 제어는 현재 출처 내에서 로드하는 리소스만 허용하면서 예외적으로 인라인 코드 사용을 허용하고 있습니다. |
| script-src 'self' 'nonce-{nonce}' | 스크립트 태그 관련 권한과 출처는 현재 출처 내에서 로드하는 리소스만 허용하면서 예외적으로 nonce 속성을 설정하여 인라인 코드 사용을 허용 합니다. |

nonce를 예측 할 수는 없기 때문에 <font color='#4ADE80'>같은 출처 내에서 파일을 업로드하거나 내가 원하는 내용을 반환하는 페이지로 정보를 받아오는 방식을 통해 공격을 수행</font> 해야 될 것 같습니다.

**@app.route("/vuln")**
```python
@app.route("/vuln")
def vuln():
    param = request.args.get("param", "")
    return param
```

**XssBypass** 문제와 같이 param값을 검증없이 리턴합니다.
즉, xss 스크립트 삽입이 가능할 것으로 생각 됩니다.

**@app.route("/flag", methods=["GET", "POST"])**
```python
@app.route("/flag", methods=["GET", "POST"])
def flag():
    if request.method == "GET":
        return render_template("flag.html", nonce=nonce)
    elif request.method == "POST":
        param = request.form.get("param")
        if not check_xss(param, {"name": "flag", "value": FLAG.strip()}):
            return f'<script nonce={nonce}>alert("wrong??");history.go(-1);</script>'

        return f'<script nonce={nonce}>alert("good");history.go(-1);</script>'

```
1. GET 메서드로 이용자에게 URL을 입력받는 페이지를 제공하고 있습니다.
2. POST 메서드로 param 값에 name은 flag 이면서 value 값으로 진짜 FLAG를 포함하여 check_xss 함수를 호출합니다.


**check_xss**
```python
def check_xss(param, cookie={"name": "name", "value": "value"}):
    url = f"http://127.0.0.1:8000/vuln?param={urllib.parse.quote(param)}"
    return read_url(url, cookie)
```

이용자의 param값과 FLAG 값이 들어있는 cookie 값을 가지고 read_url 함수를 호출 합니다.<br>
이때 url 주소는 vuln 페이지인 http://127.0.0.1:8000/vuln?param= 입니다.

**/memo**
```python
@app.route("/memo")
def memo():
    global memo_text
    text = request.args.get("memo", "")
    memo_text += text + "\n"
    return render_template("memo.html", memo=memo_text, nonce=nonce)

```
render_template 함수를 사용하여 전달 된 변수를 HTML 엔티티코드로 변환해 저장하고 있습니다.

## 2. 가설 설정
<div class="notice--info"> 

(1) nonce 속성을 활용 중이기 때문에 같은 출처 내에서 파일을 업로드하거나 내가 원하는 내용을 반환하는 페이지를 업로드 해야 합니다.<br>

(2) CSP 설정으로 인해 인라인 코드를 사용할 수 없으니 `<script src=>` 속성을 사용하여 스크립트 파일을 불러와야 합니다.<br>

(3) memo 페이지가 존재하니 memo페이지에서 결과를 확인하기 위해 'memo?memo='+ document.cookie와 같은 스크립트를 사용 할 수 있습니다.<br>

(4) 이때 URL 인코딩을 거치지 않고 `+` 기호를 사용하게 되면 공백으로 바뀔 수 있으니 `%2b`로 대체 해서 사용하였습니다.<br>

</div>


## 3. 페이로드 작성

### 1. 인라인 코드 허용 우회
{: .no_toc}

 CSP 보안 정책으로 인해 인라인 코드를 사용 할 수 없게 되었습니다.<br>
 이럴 때 스크립트 파일을 불러올 수 있는 코드가 바로 `script의 src` 속성입니다.<br>

 예시를 들어보겠습니다.<br>

**인라인 코드 사용 O**
 ```javascript
<script>alert(1)</script>
 ```

**인라인 코드 사용 X**
 ```javascript
<script src="alert.js"></script>
 ```

 이러한 방식을 통해 인라인 코드를 사용하지 않고 스크립트를 실행 시킬 수 있습니다.<br>

### 2. script-src 'self'
{: .no_toc}

서버 응답 헤더를 보면 `script-src 'self' 'nonce-{nonce}'`와 같이 스크립트 실행 권한과 출처를 제어하고 있습니다.<br>
`'self'` 지시문은 동일 출처에서 로드되는 스크립트를 허용하므로, 이를 우회하기 위해 사용자 입력값이 그대로 반환되는 **/vuln?param** 엔드포인트를 스크립트 출처로 활용하여 실행해야 합니다.<br>


### 3. URL 인코딩 
{: .no_toc}

`'memo?memo='+ document.cookie`와 같이 스크립트를 작성해도 URL 인코딩이 되면서 `+` 기호가 ` `공백으로 바뀔 수 있으니 `%2b`로 대체 해서 사용해야 합니다.<br>
`'memo?memo='%2bdocument.cookie`

## 4. 시큐어 코딩

### (1). base - uri 설정

이번 문제를 해결할 때는 사용하지 못했지만 바로 다음에 소개해드릴 **CSP Bypass Advanced** 문제에서는 <font color='#4ADE80'>base-uri 미설정</font>으로 인한 취약점을 통해 문제를 해결해 나갔습니다.<br>

base-uri 지시문을 별도로 지정하지 않으면, 브라우저는 기본적으로 모든 출처의 `<base>` 태그 삽입을 허용하게 됩니다.<br>
따라서 추후 상대 경로를 `/vuln` 페이지에 추가 하였을 때 우회 통로로 악용될 수 있기 때문에 미리 base-uri 지시문을 설정해주는 것 입니다.<br>

실제로 다음 문제에서는 `/vuln` 페이지의 HTML 코드를 확인해보면 상대 경로가 추가 되어 있는 것을 확인 할 수 있습니다!<br>

## (2). vuln 출력 값 엔티티 이스케이프

이 문제에서 <font color='#4ADE80'>가장 쉽게 찾을 수 있는 취약점은 아무래도 사용자 입력 값을 검증 없이 그대로 반환</font>한다는 점입니다.<br>
이를 방지하기 위해서는 `/memo` 페이지에서 사용한 것 처럼 <font color='#4ADE80'>HTML 태그로 해석될 수 있는 특수 문자(<,>",',&등)를 HTML 엔티티 코드로 변환</font>하여 단순 문자열로 처리해야 합니다.<br>

<div style="text-align: center; margin: 20px 0;">
  <img src="{{ '/images/CPSBypass/security.png' | relative_url }}" 
       alt="보안 설정 추가" 
       style="max-width: 80%; height: auto; border: 1px solid #ddd; border-radius: 5px;">
  <p style="font-size: 0.9em; color: #666;">[보안 설정 추가]</p>
</div>

## 5. 마치며

이번 문제를 해결한 뒤 곧바로 다음 문제인 CSP Bypass Advanced를 풀어보았습니다. 문제를 해결하는 과정에서 문득 *'왜 이전 문제에서는 <base> 태그를 이용한 우회가 불가능했을까?'*라는 의문이 생겼습니다.<br>

이 질문을 다시 고민해 보면서, 제가 놓치고 있었던 부분과 <base> 태그를 이용한 우회가 가능하기 위해 필요한 조건들을 더욱 명확하게 이해할 수 있었습니다.<br> 
단순히 문제를 푸는 것에서 끝나는 것이 아니라, 이전 문제와 비교하며 원인을 분석하는 과정이 CSP를 이해하는 데 큰 도움이 되었습니다.<br>

다음 글에서는 CSP Bypass Advanced 문제를 소개하고, 이전 문제에서는 적용되지 않았던 <base> 태그 기법이 왜 Advanced 문제에서는 가능한지 그 이유를 함께 살펴보겠습니다.<br> 
또한 두 문제를 비교하며 배운 점과 새롭게 알게 된 내용을 정리해 보겠습니다.<br>
**긴 글 읽어주셔서 감사합니다!**