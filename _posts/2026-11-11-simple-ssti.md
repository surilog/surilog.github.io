---
layout: single
title: '[Dreamhack] simple-ssti 풀이 및 Jinja2 템플릿 인젝션 취약점 분석'
sidebar:
    nav: "main"
tag : [Dreamhack, WebHacking, SSRF, PortScanning, Python, Security, Writeup]
categories: [Web, Wargame]
toc : true
toc_sticky: true
toc_label: "Contents"
author_profile: true
search: true
comments: true
published: false
---

<div class="notice--info">  
본 포스팅은 Dreamhack의 simple_ssrf 워게임 문제를 분석한 기록입니다. (드림핵 가이드라인을 준수하여 FLAG 직접 노출은 지양하고 핵심 분석 위주로 정리했습니다.)

</div>

<div style="text-align: center; margin: 20px 0;">
  <img src="{{ '/images/simple_crack_me2/note1.jpg' | relative_url }}" 
       alt="필기 노트" 
       style="max-width: 80%; height: auto; border: 1px solid #ddd; border-radius: 5px;">
  <p style="font-size: 0.9em; color: #666;">[ 필기 노트]</p>
</div>

# [Dreamhack] simple_ssti

- 날짜: 2026-11-09
- 분야: 웹해킹
- 도움 받은 정도: 1단계 · 혼자 고민하기

## 1. 개요 및 핵심 요약

Flask 404 에러 핸들러가 `request.path`를 **템플릿 문자열에 먼저 끼워 넣은 뒤** `render_template_string`으로 렌더링하는 SSTI 문제다. URL 경로에 `{{5*5}}`를 넣어 취약점을 확인하고, `{{config}}`로 서버 설정 값(`SECRET_KEY`)을 읽어 플래그를 얻었다.

## 2. THINK · 분석

- 파이썬 Flask로 만든 웹 페이지이고, Flask는 템플릿 엔진으로 **Jinja2**를 사용한다.
- 소스코드에서 확인이 필요한 곳은 404 에러 핸들러다.

```python
@app.errorhandler(404)
def Error404(e):
    template = '''
    <div class="center">
        <h1>Page Not Found.</h1>
        <h3>%s</h3>
    </div>
''' % (request.path)
    return render_template_string(template), 404
```

- 소스코드에는 다음과 같이 플래그가 `secret_key`에 직접 들어가는 부분이 있다.

```python
app = Flask(__name__)

try:
    FLAG = open('./flag.txt', 'r').read()
except:
    FLAG = '[**FLAG**]'

app.secret_key = FLAG
```

  `app.secret_key = 값`은 `app.config['SECRET_KEY'] = 값`과 같은 동작이다. Flask 객체의 `secret_key` 속성이 내부적으로 `config['SECRET_KEY']`를 읽고 쓰도록 연결되어 있기 때문이다. 그래서 `{{config}}`로 설정 객체를 출력하면 그 안에 `SECRET_KEY` 키로 플래그가 그대로 노출된다. **이게 CREATE 단계에서 `{{config}}`를 가장 먼저 확인하기로 한 선택이 적중한 이유다.**
- 핵심은 `% (request.path)`다. 사용자가 입력한 URL 경로가 **템플릿 소스 자체**에 합쳐진 다음 렌더링된다. 그래서 입력값이 "데이터"가 아니라 "템플릿 구문"으로 해석된다.
- **SSTI(Server-Side Template Injection)**: 사용자 입력이 템플릿 코드의 일부로 삽입되어 서버에서 평가되는 취약점이다.
- XSS, CSRF 같은 Client-side 공격과 달리 서버에서 실행되므로, 템플릿 컨텍스트에서 닿을 수 있는 범위에 따라 정보 노출이나 RCE까지 이어질 수 있다.

## 3. CREATE · 설계

1. **입력 지점 찾기**: 존재하지 않는 경로를 요청하면 404 핸들러가 호출되고, 이때 `request.path`가 템플릿에 들어간다.
2. **평가 여부 확인**: `{{5*5}}`를 넣어 `25`가 출력되면 입력이 템플릿 구문으로 평가되고 있다는 뜻이므로 SSTI가 성립한다. 단순 문자열이라면 `{{5*5}}`가 그대로 출력된다. 결과가 눈에 바로 보이는 연산이라 탐지용으로 적합하다.
3. **노릴 대상 정하기**: Flask는 `config`, `request`, `session`, `g` 등을 Jinja2 기본 컨텍스트로 제공한다. 그중 `config`에는 서버 동작에 관한 설정과 `SECRET_KEY` 같은 민감 값이 담길 수 있으므로 `{{config}}`를 먼저 확인한다.
4. **만약 `config`에 없었다면(가설, 이번 문제에서는 사용하지 않음)**: `{{"".__class__.__base__.__subclasses__()}}`로 `object`의 서브 클래스 목록을 얻고, 그중 `subprocess.Popen`을 찾아 `{{"".__class__.__base__.__subclasses__()[N]('dir', shell=True, stdout=-1).communicate()}}`처럼 호출해 명령어를 실행시키는 RCE까지 생각해 두었다. `N`은 서버 환경마다 달라지므로 실제로는 목록을 출력해서 직접 찾아야 한다.

## 4. SOLVE · 검증

**1) SSTI 확인**

- URL 뒤에 `{{5*5}}`를 붙여 요청 → 에러 페이지에 `25` 출력 → 성공

**2) `{{config}}` 삽입**

- Flask 설정 객체가 그대로 출력되고, 그 안의 `SECRET_KEY` 값이 플래그였다.

```text
/404Error<Config {'DEBUG': False, ..., 'SECRET_KEY': 'DH{...}', ...}>
```

> 플래그 값은 `DH{...}`로 가렸다. 공개 블로그나 저장소에 올릴 때도 이렇게 가리는 편이 안전하다.

**3) 시행착오**

- 처음에는 `{{5*5}}`를 브라우저 개발자 도구의 요소(Elements) 탭에서 소스코드에 직접 넣어 봤다. 결과는 `25`가 아니라 글자 그대로 나왔다.
- 개발자 도구에서 고친 내용은 **내 브라우저가 가진 HTML(DOM)만 바꾼 것**이고, 서버로 전송되지 않는다. 템플릿 엔진은 서버에서 동작하므로 서버에 요청이 가지 않으면 평가될 수 없다.
- 문제 소스를 다시 읽다가 404 핸들러의 `% (request.path)`를 발견했고, 입력이 서버로 들어가는 지점이 URL 경로라는 것을 알았다. URL 맨 뒤에 `{{5*5}}`를 넣어 요청하니 성공했다.
- 교훈: SSTI는 **서버로 요청을 보내야** 확인할 수 있다. 입력이 서버로 가는 지점(URL, 파라미터 등)을 먼저 찾아야 한다.

## 5. 배운 것 · 다음에 비슷한 문제를 만나면

- 템플릿 엔진을 쓰더라도 **사용자 입력을 템플릿 문자열에 직접 합치면** 입력이 코드로 평가된다. (`%`, f-string, `+` 모두 마찬가지)
- 안전한 방식은 입력을 컨텍스트 변수로 전달하는 것이다.

```python
# 취약
render_template_string("<h3>%s</h3>" % request.path)

# 안전
render_template_string("<h3>{{ path }}</h3>", path=request.path)
```

- 탐지는 `{{5*5}}`처럼 결과가 눈에 보이는 연산으로 한다. 엔진마다 문법이 다르므로 **엔진별 문법과 페이로드를 구분해서 익혀 둔다.**
- 실제 서비스에서 `SECRET_KEY`가 유출되면 Flask 세션 쿠키 서명을 위조할 수 있어 심각하다. 이 문제에서는 설정 노출 자체가 목표였다.

## 6. 대응 방안 (시큐어 코딩)

### 1) Sanitization — `render_template_string()` 대신 `render_template()` 사용

가장 근본적인 대응은 사용자 입력으로 템플릿 문자열 자체를 만들지 않는 것이다. `render_template()`은 `templates` 디렉터리에 미리 작성해 둔 HTML 파일을 렌더링하며, 그 파일에 없는 `{{ }}` 구문은 해석하지 않고 문자열로 그대로 출력한다.

```python
# 취약한 코드 (이번 문제의 구조)
@app.errorhandler(404)
def Error404(e):
    template = '''
    <div class="center">
        <h1>Page Not Found.</h1>
        <h3>%s</h3>
    </div>
''' % (request.path)
    return render_template_string(template), 404
```

```python
# 안전한 코드
# templates/404.html
# <div class="center">
#     <h1>Page Not Found.</h1>
#     <h3>{{ path }}</h3>
# </div>

@app.errorhandler(404)
def Error404(e):
    return render_template('404.html', path=request.path), 404
```

`render_template_string()`을 꼭 써야 한다면, 최소한 입력을 문자열 포맷팅으로 템플릿 소스에 합치지 말고 아래처럼 변수로 전달해야 한다.

```python
# render_template_string을 쓰더라도 안전하게
template = '<h3>{{ path }}</h3>'
return render_template_string(template, path=request.path), 404
```

### 2) Input Validation — 특수문자 필터링·치환

Sanitization을 적용하기 어려운 상황이라면 보조 수단으로 `{`, `}`, `[`, `]` 등 SSTI 공격에 쓰이는 핵심 특수문자를 정규 표현식으로 걸러낸다.

```python
import re

def contains_ssti_payload(value: str) -> bool:
    # SSTI 공격에 자주 쓰이는 특수문자를 탐지
    pattern = re.compile(r'[{}\[\]]')
    return bool(pattern.search(value))

@app.errorhandler(404)
def Error404(e):
    path = request.path
    if contains_ssti_payload(path):
        abort(403)  # 또는 특수문자를 제거/치환 후 진행
    template = '<h3>%s</h3>' % path
    return render_template_string(template), 404
```

다만 이 방식은 우회 가능성이 남아 있는 **보조 대응**일 뿐이다. 근본 대응은 1)번처럼 입력을 템플릿 구문으로 합치지 않는 것이다.

### 3) 참고: Sandbox

템플릿 엔진 실행 환경 자체를 격리하는 방법도 있으나, 이번 학습 범위에서는 다루지 않았다.

## 7. 참고: RCE로의 확장 경로 (CREATE 단계에서 세운 가설, 이번 문제에서는 사용하지 않음)

`config`에 플래그가 없었다면 다음 단계까지 생각해 두었다.

1. 빈 문자열의 `__class__`로 `str` 클래스에 접근한다.
2. `__base__`로 최상위 클래스 `object`에 도달한다.
3. `__subclasses__()`로 서브 클래스 목록을 얻고, 그중 `subprocess.Popen`을 찾는다.
4. `subprocess.Popen('dir', shell=True, stdout=-1).communicate()`를 호출해 서버에서 `dir` 명령을 실행시키고 결과를 받아온다. `shell=True`는 서브 셸에서 명령을 실행하게 하고, `stdout=-1`은 `subprocess.PIPE`를 의미해 표준 출력을 받아올 수 있게 한다.
5. 서브 클래스 목록의 인덱스는 서버 환경(파이썬 버전, OS, 설치된 모듈)마다 다르므로 목록을 출력해서 직접 확인해야 한다.
6. 이 단계까지 가면 서버에서 임의 명령이 실행되는 것이므로 **RCE(Remote Code Execution)**로 분류된다.

## 8. 핵심 키워드

- `SSTI`: 사용자 입력이 템플릿 코드로 평가되는 서버 측 취약점
- `Jinja2`: Flask가 기본으로 쓰는 템플릿 엔진
- `render_template_string()`: 문자열을 템플릿으로 렌더링하는 함수. 입력을 그 문자열에 합치면 위험하다.
- `request.path`: 요청 URL 경로. 이 문제에서 입력이 들어가는 지점이다.
- `config`: Flask가 Jinja2 기본 컨텍스트로 제공하는 설정 객체. `SECRET_KEY` 등이 들어 있다.
- `render_template()`: `templates` 디렉터리의 파일을 렌더링한다. 입력의 템플릿 구문을 문자열로 처리하므로 안전하다.

## 9. 참고 자료

- 이글루코퍼레이션 보안정보, [웹 템플릿 엔진 기반의 SSTI 취약점 분석](https://www.igloo.co.kr/security-information/%EC%9B%B9-%ED%85%9C%ED%94%8C%EB%A6%BF-%EC%97%94%EC%A7%84-%EA%B8%B0%EB%B0%98%EC%9D%98-ssti-%EC%B7%A8%EC%95%BD%EC%A0%90-%EB%B6%84%EC%84%9D/) (2022.09.03) — SSTI 개념, Jinja2 문법, 탐지와 대응 방법 학습에 활용
- [Flask Templating 문서](https://flask-docs-ja.readthedocs.io/en/latest/templating/) — Jinja2 기본 컨텍스트(`config`, `request` 등) 확인
