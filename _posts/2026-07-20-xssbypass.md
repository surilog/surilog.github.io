---
layout: single
title: 'Dreamhack XSS Filtering Bypass Advanced 를 통해 배우는 자바스크립트 함수 및 키워트 필터링'
sidebar:
    nav: "main"
tag : [dreamhack, web, 웹 해킹, exploit, xss, 창, HTTP 엔티티, HTTP 엔티티 이스케이프, Http-Only]
categories: [wargame, 보안]
toc : true
toc_sticky: true
toc_label: "Contents"
author_profile: true
search: true
comments: true
published: false
---

<div class="notice--success">  
본 포스팅은 드림핵의 가이드라인을 준수하여 작성되었습니다. 전체 익스플로잇 스크립트나 FLAG 값은 포함하지 않으며, 취약점의 원리 분석과 방어 대책에 집중합니다.
</div>

안녕하세요! 오늘은 드림핵(Dreamhack)의 **XSS Filtering Bypass Advanced** 워게임 문제를 풀어보며 자바스크립트 함수 및 키워드를 필터링하여 페이로드를 작성해내는 과정의 공부 기록에 대해 소개해보려고 합니다.<br>


문제를 풀기 전, 제가 스스로 취약점을 분석하고 공격 로직을 세우기 위해 디딤돌로 삼았던 드림핵 공식 학습 링크와 챌린지 주소를 아래에 공유합니다.<br>

## 🔗 주요 관련 링크 바로가기

| 구분 | 링크 안내 |
| :--- | :--- |
| **워게임 도전** | [🎯 드림핵 공식 XSS Filtering Bypass Advanced 워게임 챌린지 링크](https://dreamhack.io/wargame/challenges/434) |
| **관련 강의** | [🎯 드림핵 공식 Switching Command 워게임 챌린지 링크](https://learn.dreamhack.io/318) |


이 문제의 핵심은 주어진 필터링을 우회하여 xss스크립트를 삽입하는 것입니다.<br>

## 1. 코드 분석


```python
@app.route("/flag", methods=["GET", "POST"])
def flag():
    if request.method == "GET":
        return render_template("flag.html")
    elif request.method == "POST":
        param = request.form.get("param")
        if not check_xss(param, {"name": "flag", "value": FLAG.strip()}):
            return '<script>alert("wrong??");history.go(-1);</script>'
#check_xss에 param와 name은 flag 값으로는 진짜 flag 값이 전달됨.
        return '<script>alert("good");history.go(-1);</script>'
```
**제출** 버튼을 눌렀을 때 제가 적은 `param` 값과 `flag`라는 이름의 진짜 `FLAG` 값을 `check_xss` 함수로 보내고 에러가 나면 wrong 에러가 나지 않으면 good을 띄웁니다.<br>

```python
def check_xss(param, cookie={"name": "name", "value": "value"}):
    url = f"http://127.0.0.1:8000/vuln?param={urllib.parse.quote(param)}"
    return read_url(url, cookie)
```
cookie의 value값에 진짜 FLAG가 들어있으니 cookie 값을 탈취해야 함을 알 수 있었습니다.<br>
`vuln`페이지에서는 자바스크립트 명령어가 실행 되므로 param값에 스크립트를 작성 해야 함을 알 수 있습니다.<br>



```python
def xss_filter(text):
    _filter = ["script", "on", "javascript"]
    for f in _filter:
        if f in text.lower():
            return "filtered!!!"
#단어가 발견되면 차단! 삭제가 아니라 차단!
    advanced_filter = ["window", "self", "this", "document", "location", "(", ")", "&#"]
    for f in advanced_filter:
        if f in text.lower():
            return "filtered!!!"
#()는 URL[][]로 우회
# @#이 필터링 된 것으로보아 특수문자 사용은 힘들어 보임
    return text
#우회 명령어와 특수문자 필터링이 추가됨.
```

이 문제 전 bypass문제에서 필터링이 더 업그레이드 되었습니다.<br>
1. `script, on, javascript` 가 존재하면 삭제하는 것이 아니라 아예 차단됩니다.<br>
2.  `"window", "self", "this", "document", "location", "(", ")", "&#"`
이와 같은 자바스크립트 함수와 키워트 필터링이 추가되었습니다.<br>

```python
@app.route("/vuln")
def vuln():
    param = request.args.get("param", "")
    param = xss_filter(param)
    return param
```
이용자가 입력한 `param` 값을 `xss_filer()`함수 하나만 믿고 함수를 통과하면 바로 그 값을 화면에 띄워 보여줍니다.<br>

```python
@app.route("/memo")
def memo():
    global memo_text
    text = request.args.get("memo", "")
    memo_text += text + "\n"
    return render_template("memo.html", memo=memo_text)
```

`memo`페이지에서는 `render_template`를 거쳐서 출력되므로 자바스크립트가 실행되지 않고 단순 글자로만 찍힙니다.<br>
여기서 저는 명령어를 실행 할 수는 없지만 실행된 결과를 확인 할 수 있다고 생각했습니다.<br>


## 2. 가설 설정

(1)FLAG는 cookie 값에 존재합니다.<br>

(2)cookie는 "http://127.0.0.1:8000/vuln?param={urllib.parse.quote(param)}" 페이지에 같이 있게 됩니다<br>

(3)vuln페이지는 javascript 명령어가 작동하는 페이지입니다.<br>

(4) vuln 페이지에서 스크립트를 삽입해 memo 페이지에서 확인을 하면 FLAG를 확인 할 수 있습니다.<br>

## 3. 페이로드 작성 과정

### 1. script 태그와 on 핸들러 우회
{: .no_toc}

(1).`script`태그 그리고 `on` 핸들러가 필터링 되어 있어 이를 대체할만한 HTML 태그가 필요 해서 <font color='#4ADE80'>iframe</font>태그를 활용했습니다.<br>
`img` 태그를 사용할까 하다가 `on`핸들러가 필터링 되어 있는 것을 보고 노선을 바꿨습니다!<br>

### 2. javascript 필터링 우회
{: .no_toc}

(2). `iframe src=javascript:` 형식으로 작성해야 javascript코드가 실행이 되는데 javascript 문자열 자체가 필터링 되어있어 우회가 필요했습니다.<br>
그래서<font color='#4ADE80'> 코드가 실행되기 전 자동으로 제거되는 탭 문자 엔티티(`&Tab`)를 삽입하여 우회</font> 하였습니다.<br>

<div class="notice--info">  
1. `xss_filter` 에서는 javascrip&amp;Tab;t라는 단어를 보고 통과<br>

2. 웹 브라우저에 코드가 도착한다면 HTML 표준 규약에 따라 특수 문자들을 디코딩<br>
즉, &amp;Tab;을 진짜 탭 공백`(\t)` 으로 바꿔 주어 javascrip  t:로 변환<br>

3. 브라우저는 사용자가 공백을 주소창에 실수로 넣어도 이를 알아서 지우고 접속해주는 공백 제거 기능을 가지고 있기 때문에 

최종적으로 javascript: 프로토콜로 인식하게 됩니다!<br>
</div>

### 3. advanced_filter 우회
{: .no_toc}

(3). `"window", "self", "this", "document", "location", "(", ")", "&#"`와 같은 문자열과 특수 문자들이 필터링 되어 있기 때문에 우회가 필요했습니다.<br>

그래서 저는 <font color='#4ADE80'> window대신 \u0077indow 같은 형태로 유니코드 이스케이프 시퀀스를 작성하여 우회</font> 하였습니다.<br>

<div class="notice--info">  
1. `xss_filter` 에서는 `\u0077indow` 단어를 보고 통과<br>
2. 자바스크립트 엔진에서는 **유니코드 이스케이프 문자**를 디코딩.<br>
3. 결국 `window[]`로 사용!<br>
</div>
이와 같은 방법으로 **document**도 우회하여 스크립트를 작성했습니다.<br>

### 4. 대괄호 우회 방법
{: .no_toc}

이번 문제 `location.href=` 형식을 활용하여 <font color='#4ADE80'>memo페이지로 FLAG 값을 이동시켜 확인</font>하고자 하였는데 location 문자열 자체에 필터링이 되어 있어 우회가 필요했습니다.<br>

<font color='#4ADE80'>필터링을 피해 location.href=형식을 활용하기 위해 대괄호를 활용하였습니다.</font><br>
자바 스크립트에서는 객체의 속성에 접근할 때 아래의 두가지 방법이 완벽하게 동일하게 취급됩니다.<br>

| 구분 | 표기법 |
| :--- | :--- |
| **점 표기법** | `top.location.href` |
| **대괄호 표기법** | `top['locatio'+'n'].href` |

여기서 주목할 점은 괄호 안에 **문자열**이 들어간다는 것이며 자바 스크립트 엔진은 괄호 안의 연산을 가장 먼저 수행하므로, 코드가 실행되는 순간 ['location'] 문자열로 만듭니다.<br>

<div class="notice--info"> 
1. `xss_filter` 에서는 top['locatio'+'n'].href 를 보고 통과<br>
2. 자바스크립트 엔진은 top['location'].href로 가장 먼저 괄호 안의 연산을 수행.<br>
3. 브라우저는 결국 top.location.href로 완벽하게 이해하고 실행하게 됩니다.
</div>

### [+] 유니코드 우회 핵심 포인트
{: .no_toc}

-반드시 **변수 이름(식별자)** 자리에 쓰여야 한다.
```javascript
\u0077indow.location = ...
// 자바스크립트 엔진이 코드를 실행할 때 진짜 변수인 window로 변환해 줌!
```

```javascript
top['\u0077indow']
// 따옴표 안에 넣으면 엔진이 변수명으로 보지 않고 그냥 "\u0077indow"라는 '글자' 자체로 취급합니다. 
// 만약 서버 필터가 따옴표 안의 단어까지 다 막고 있다면 문자열 쪼개기('win'+'dow')를 써야 하는 이유가 바로 이 때문입니다.
```

여기서부터는 **창**의 기본적인 개념에 대해 다루면서 소개하겠습니다.<br>

### [+] this, self가 아닌 window를 사용한 이유
{: .no_toc}

#### (1)브라우저의 특성
{: .no_toc}

<font color='#4ADE80'>브라우저는 보안을 위해 부모 창과 자식 창을 독립된 별개의 방으로 취급</font>합니다.<br>
제가 사용한 `<iframe>` 코드로 비유를 들어보겠습니다.<br>
<font color='#4ADE80'>부모 창이 거실이라면 iframe은 자식 창으로 거실 안의 텐트</font>느낌으로 존재합니다.<br>

이 문제 같은 경우에는 FLAG가 부모 창에 존재하기 때문에 자식 창에서만 동작하는 스크립트는 의미가 없습니다.<br>
그 스크립트가 결국 부모 창에 영향을 줄 수 있어야 합니다.<br>


#### (2)`self`와 `this`
{: .no_toc}

먼저 `self`와 `this`는 모두 기본적으로 현재 실행 중인 코드의 방(창)을 가리키는 존재입니다.<br>

차이점 `self`: **언제 어디서 불러도 자기 자신을 의미**<br>
다시 말해서<font color='#00eeff'> 부모 창에서 부르면 self는 부모창이 되고 자식 창에서 부르면 self는 자식 창이 됩니다.</font><br>

`this`: 일반적인 웹 페이지에서 `this`를 쓰면 `window`(현재 창)을 가리키게 됩니다.<br>
하지만 저는 `<iframe>`를 사용하였고<font color='#4adcde'> `<iframe src>` 내부에서는 이를 일반적인 웹 페이지가 아니라 `src`라는 `HTML 속성값` 안에서 돌아가는 특수한 환경으로 이해</font>하게 됩니다.<br>

그래서 이때의 `this`는 `window`를 가리키는 것이 아니라 `undefined` 또는 해당 iframe라는 `HTML` 태그 자체를 가리키게 됩니다.<br>

#### (3) FLAG가 들어 있는 최상위 부모 창 <br>
{: .no_toc}

먼저 `window`는 거실, 텐트 개념이 아니라 그 건물 자체로 **고유 명사 취급**됩니다.<br>
즉, 다시 말해서 전역 공간에 등록된 식별자로 alert나 location도 원래는 window.alert, window.location 와 같이 사용되어야 하지만 window는 고유명사로 취급되어 컴퓨터가 다 알아듣기 때문에 window를 빼고 사용 할 수 있습니다.<br>

이 문제에서는 <font color='#f94444'>부모 창과 자식 창이 같은 도메인에 존재</font>합니다.<br>
<font color='#4ADE80'>결국 `window`를 사용하게 된다면 같은 도메인에 있기 때문에 쿠키를 가져오는 유효한 요청을 보내면 FLAG를 구할 수 있게 됩니다.</font><br>

다음으로 `top`은 `<iframe>`이 얼마나 깊게 들어가 있던 상관없이,<font color='#4ADE80'> 브라우저 탭의 가장 최상위에 있는 진짜 부모 창을 강제로 가리키게 합니다.</font>
즉, `top`을 사용하게 된다면 `<iframe>` 내부의 자식 창이 아닌 그 위에 있는 부모 창에서 코드를 실행 할 수 있게 해줍니다.

## 4. 시큐어 코딩

### (1). HTML 엔티티 이스케이프
{: .no_toc}

웹 브라우저는 `<script>, <iframe>, <img>` 같은 특수문자를 만나면 이를 실행해야 할 "HTML 태그"로 인식합니다.

<font color='#4ADE80'>HTML 엔티티 이스케이프는 사용자가 입력한 데이터 중 브라우저가 명령어로 오해할 수 있는 특수문자들을 단순히 화면에 보여주기만 하는 안전한 텍스트 기호(HTML Entity)로 바꿔서 출력</font>하는 기술입니다.


| 특수문자 | 변환된 HTML 엔티티 | | 브라우저의 인식 |
| :--- | :--- | :--- |
| **<** | `&lt;` | 태그의 시작이 아닌 단순 "작다"기호
| **>** | `&gt;` | 태그의 끝이 아닌 단순 "크다"기호
| **"** | `&quot;` | 속성값을 감싸는 따음표가 아닌 글자 큰 따음표
| **'** | `&gt;` | 속성값을 감싸는 따음표가 아닌 글자 작은 따음표
| **&** | `&amp;` | 엔티티 시작 기호가 아닌 단순 앤드(&) 기호

```python

import markupsafe  # 텍스트에 섞여 들어온 위험한 특수 문자들을 안전한 HTML 엔티티로 변환해 주는 초고속 텍스트 이스케이프 라이브러리

def xss_filter_secure(text):
    # <, >, &, ", ' 등의 특수문자를 &lt;, &gt;, &amp; 등으로 자동 변환
    return str(markupsafe.escape(text))

    @app.route("/vuln")
def vuln():
    param = request.args.get("param", "")
    # 검증되지 않은 블랙리스트 대신 HTML 이스케이프 적용
    clean_param = xss_filter_secure(param)
    return clean_param

```
**이스케이프 적용 전:**
공격자가 `<script>alert(1)</script>`를 입력하면 브라우저는 `<script>` 태그를 해석하여 자바스크립트 코드 `alert(1)`을 실행합니다.

**이스케이프 적용 후:**
서버가 입력값을 `&lt;script&gt;alert(1)&lt;/script&gt;`로 변환하여 전달합니다.
브라우저는 이를 태그가 아닌 단순 문장으로 인식하여, 화면에 그저 `<script>alert(1)</script>`라는 글자 그대로 출력만 하고 코드는 절대 실행하지 않습니다.

### (2). HTTP-Only 쿠키 설정
{: .no_toc}

웹 브라우저의 자바스크립트는 기본적으로 **document.cookie**라는 명령어를 통해 현재 페이지의 모든 쿠키 정보에 접근할 수 있습니다.

<font color='#4ADE80'>HttpOnly는 서버가 브라우저에게 쿠키를 발급할 때 "이 쿠키는 오직 HTTP 통신(서버 요청)을 할 때만 전달하고, 자바스크립트로 접근하는 것은 절대 금지해!"라고 지시하는 보안 옵션</font> 입니다.

#### 동작 원리 비교
{: .no_toc}

**[일반 쿠키]**

자바스크립트(document.cookie) ──접근 가능──> 🔓 [쿠키: FLAG값] 

**[HttpOnly 쿠키]**

자바스크립트(document.cookie) ──접근 차단!──> 🔒 [쿠키: FLAG값 (HttpOnly)]<br>
웹 서버 (HTTP GET/POST 요청)  ──자동 첨부──> 🔒 [쿠키: FLAG값 (HttpOnly)]


HttpOnly 설정 시 웹 사이트에서 XSS공격 코드가 실행되는 사고가 발생하더라도, 자바스크립트가 **document.cookie**를 조회해도 빈 값(" ")만 반환되게 합니다.

```python
@app.route("/flag", methods=["GET", "POST"])
def flag():
    if request.method == "GET":
        return render_template("flag.html")
    elif request.method == "POST":
        param = request.form.get("param")
        
        # 관리자 봇 쿠키 생성 시 HttpOnly=True 속성을 부여하도록 설정했기 때문에 
        # 자바스크립트(document.cookie)로 쿠키에 접근하는 것을 브라우저 단에서 차단합니다.
        cookie = {"name": "flag", "value": FLAG.strip(), "httponly": True}
        
        if not check_xss(param, cookie):
            return '<script>alert("wrong??");history.go(-1);</script>'
        return '<script>alert("good");history.go(-1);</script>'
```


### (3). Codespace 적용
{: .no_toc}

<div style="text-align: center; margin: 20px 0;">
  <img src="{{ '/images/XSS-Filtering-Bypass-Advanced/code.png' | relative_url }}" 
       alt="XSS 방어 코드" 
       style="max-width: 80%; height: auto; border: 1px solid #ddd; border-radius: 5px;">
  <p style="font-size: 0.9em; color: #666;">[XSS 방어 코드]</p>
</div>

<div style="text-align: center; margin: 20px 0;">
  <img src="{{ '/images/XSS-Filtering-Bypass-Advanced/secure.png' | relative_url }}" 
       alt="XSS 방어" 
       style="max-width: 80%; height: auto; border: 1px solid #ddd; border-radius: 5px;">
  <p style="font-size: 0.9em; color: #666;">[방어 성공]</p>
</div>

## 5. 마치며

이번 드림핵의 XSS Filtering Bypass Advanced 문제는 자바스크립트의 문법적 특성을 활용해 블랙리스트 필터링을 우회하고, 상황에 맞는 페이로드를 설계해 보는 재미가 있었던 문제였습니다.<br>

공격 기법 분석에서 그치지 않고 HTML 엔티티 이스케이프와 HttpOnly 쿠키 설정을 통한 시큐어 코딩 기법까지 직접 정리해 보면서, XSS 취약점의 공격과 방어 메커니즘을 전반적으로 깊이 있게 이해할 수 있었습니다.