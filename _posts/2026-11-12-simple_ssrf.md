---
layout: single
title: '[Dreamhack] simple_ssrf 풀이 및 SSRF 기반 로컬 포트 스캐닝 분석'
sidebar:
    nav: "main"
tag: [Dreamhack, WebHacking, SSRF, PortScanning, Python, Security, Writeup]
categories: [Web, Wargame]
toc: true
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


# [Dreamhack] web-ssrf

- 날짜: 2026-11-12
- 분야: 웹해킹
- 도움 받은 정도: 2단계 · 개념은 스스로 세우고, 코드 작성에 AI 도움

## 1. 개요 및 핵심 요약

Flask로 만든 이미지 뷰어 서비스에서 `url` 파라미터로 서버가 대신 요청을 보내주는 SSRF 문제다. `localhost`/`127.0.0.1` 문자열만 막는 블랙리스트 필터를, `127.1`이라는 축약 IP 표기로 우회했다. 플래그는 서버 내부에서만 열려 있는 두 번째 HTTP 서버(임의 포트, 1500~1800 사이)에 있었고, 그 포트 번호는 눈에 보이지 않아 응답 길이 차이를 오라클로 쓰는 포트 브루트포스로 찾아냈다.

## 2. THINK · 분석

- 파이썬 Flask + `requests` 라이브러리로 만든 웹 서비스다. `img_viewer` 라우트가 사용자가 입력한 `url`로 서버가 직접 HTTP 요청을 보내고, 그 응답(이미지)을 base64로 인코딩해 화면에 보여준다.

```python
@app.route("/img_viewer", methods=["GET", "POST"])
def img_viewer():
    ...
    elif request.method == "POST":
        url = request.form.get("url", "")
        urlp = urlparse(url)
        if url[0] == "/":
            url = "http://localhost:8000" + url
        elif ("localhost" in urlp.netloc) or ("127.0.0.1" in urlp.netloc):
            data = open("error.png", "rb").read()
            img = base64.b64encode(data).decode("utf8")
            return render_template("img_viewer.html", img=img)
        try:
            data = requests.get(url, timeout=3).content
            img = base64.b64encode(data).decode("utf8")
        except:
            data = open("error.png", "rb").read()
            img = base64.b64encode(data).decode("utf8")
        return render_template("img_viewer.html", img=img)
```

- **SSRF(Server-Side Request Forgery)**: 공격자가 입력값을 조작해 서버가 대신 위조된 HTTP 요청을 보내게 만들고, 그 결과로 외부에서 직접 접근할 수 없는 내부 자원(내부망, 로컬호스트 서비스 등)에 접근하는 공격이다. CSRF와 비슷하게 "요청 위조"라는 성격을 가지지만, 요청이 서버 측에서 일어난다는 점이 다르고, 그래서 내부망에 대한 추가 공격으로 이어질 수 있어 영향도가 더 크다.
- **취약점의 근본 원인(Root Cause)**: `netloc`에 `"localhost"`나 `"127.0.0.1"`이라는 **문자열이 포함되어 있는지**만 검사하는 블랙리스트 방식이다. 즉 같은 주소를 가리키는 다른 표기법은 전혀 걸러내지 못한다.
- **진짜 노려야 할 대상**: 소스 하단을 보면 Flask 앱(8000번 포트) 말고 내부에 또 하나의 HTTP 서버가 떠 있다.

```python
local_host = "127.0.0.1"
local_port = random.randint(1500, 1800)
local_server = http.server.HTTPServer(
    (local_host, local_port), http.server.SimpleHTTPRequestHandler
)
print(local_port)
```

  `SimpleHTTPRequestHandler`는 현재 작업 디렉터리(`/app`, 즉 `flag.txt`가 있는 곳)를 그대로 웹에 서빙하는 파이썬 내장 서버다. 이 서버는 `127.0.0.1`의 **매번 바뀌는 임의 포트**(1500~1800)에서만 열려 있고, 포트 번호는 `print()`로 서버 콘솔(사용자는 볼 수 없는 로그)에만 찍힌다.
- 즉 두 가지가 동시에 필요하다: (1) `127.0.0.1`을 가리키되 문자열 필터를 피하는 표기법, (2) 보이지 않는 임의 포트를 알아내는 방법.

**손으로 그린 공격 흐름도**

<div style="text-align: center; margin: 20px 0;">
  <img src="{{ '/images/simple_ssrf/note.png' | relative_url }}" 
       alt="SSRF 공격 흐름을 손으로 그린 다이어그램" 
       style="max-width: 80%; height: auto; border: 1px solid #ddd; border-radius: 5px;">
  <p style="font-size: 0.9em; color: #666;">[SSRF 공격 흐름을 손으로 그린 다이어그램]</p>
</div>


1. 공격자가 `url=http://127.1:PORT/`로 `img_viewer`에 요청
2. 웹서버(SSRF 지점)가 그 요청을 내부망 서버로 그대로 전달
3. 내부망 서버가 포트가 랜덤(1500~1800)이고 `127.1`로 블랙리스트를 우회당한 상태라 응답(flag 또는 `error.png`)을 돌려줌
4. 그 응답이 다시 공격자에게 돌아오고, 응답 길이 차이로 포트가 열려 있는지(open) 여부를 추론

## 3. CREATE · 설계

1. **필터 우회 표기법 찾기**: `urlp.netloc`에 `"localhost"`, `"127.0.0.1"` 문자열이 포함되는지만 검사하므로, 같은 주소를 가리키지만 그 문자열이 그대로 나타나지 않는 표기를 찾으면 된다. `127.1`, `127.2` 같은 축약형 등 여러 후보를 직접 떠올렸다.
2. **포트를 못 보는 문제 해결**: 1500~1800, 총 301개 포트를 일일이 수동으로 넣어보기엔 비효율적이라고 판단해, 자동으로 포트를 찾는 스크립트가 필요하다고 생각했다. (스크립트 작성은 AI 도움을 받았다 — 3번 참고)
3. **오라클 설계**: 서버가 던지는 응답은 두 종류뿐이다.
   - 포트가 비어 있으면(연결 실패) → `except`로 빠져서 `error.png`를 보여준다 → 응답 길이가 항상 동일
   - 포트가 열려 있으면(내부 서버가 응답) → 디렉터리 목록이나 실제 파일 데이터가 와서 → 응답 길이가 달라진다
   
   그래서 "거의 확실히 비어 있는 포트(1번)"로 기준(baseline) 길이를 구해두고, 1500~1800 각 포트의 응답 길이가 baseline과 다르면 "열린 포트"로 판단하는 방식을 세웠다.
4. **AI에게 요청한 조건**: 블랙리스트 우회(`127.1` 사용), 요청 타임아웃 설정, baseline 대비 길이 비교로 오라클을 만드는 방식은 본인이 직접 설계했고, 이 조건들을 AI에게 설명한 뒤 포트 브루트포스 스크립트(`auto_port.py`) 작성만 맡겼다.

## 4. SOLVE · 검증

**1) 블랙리스트 필터 우회 확인**

- `url=http://127.0.0.1:8000/`로 보내면 `error.png`가 돌아온다 (필터에 걸림).
- `url=http://127.1:8000/`로 보내면 정상적으로 요청이 나간다. → 필터 우회 성공.

  `127.1`이 `127.0.0.1`과 같은 주소로 해석되는 이유는 전통적인 BSD 소켓의 `inet_aton` 방식 IPv4 파싱 때문이다. 이 방식은 주소를 4개의 점(.)으로 구분된 형태뿐 아니라 2개나 3개로 줄여 쓰는 것도 허용하는데, 이때 마지막 숫자가 남은 바이트들을 채운다. `127.1`은 `127`(첫 바이트) + `1`(나머지 3바이트를 0.0.1로 채움) = `127.0.0.1`로 해석된다. 파이썬의 소켓 계층을 포함해 여러 환경에서 지금도 이 축약 표기를 받아들인다.

**2) 포트 브루트포스**

```python
# auto_port.py 핵심 로직
def get_response_len(bypass_host, port):
    inner_url = f"http://{bypass_host}:{port}/"
    response = requests.post(TARGET_HOST, data={"url": inner_url}, timeout=3)
    return len(response.text)

baseline_len = get_response_len("127.1", 1)  # 확실히 닫힌 포트로 기준값
for port in range(1500, 1801):
    length = get_response_len("127.1", port)
    if length != baseline_len:
        print(f"[+] port={port} - length={length}")
```

- 1500~1800번 포트를 순회하며 baseline과 다른 응답 길이를 가진 포트를 찾았다. (이 문제에서는 1646번이 찾아졌다.)

**3) 플래그 획득**

```python
FLAG_URL = "http://127.1:1646/flag.txt"
response = requests.post(TARGET_HOST, data={"url": FLAG_URL}, timeout=5)
# 응답 HTML의 base64 이미지 데이터를 추출해 디코딩
```

- `img_viewer`가 돌려주는 `<img src="data:image/png;base64, ...">`에서 base64 문자열을 꺼내 디코딩하면, 실제로는 이미지가 아니라 `flag.txt`의 내용(플래그)이 그대로 나왔다.

**4) 시행착오**

- 블랙리스트가 `localhost`, `127.0.0.1` "문자열 포함 여부"만 본다는 걸 소스에서 확인하고, 같은 주소를 가리키는 다른 표기법(`127.1`, `127.2` 등)이 있을 거라는 데까지는 스스로 생각해냈다.
- 하지만 1500~1800번 포트를 사람이 하나씩 넣어보는 건 비효율적이라, 반드시 자동화가 필요하다고 판단했다. 이때 블랙리스트 우회·타임아웃·오라클 설계 같은 **개념은 이미 알고 있었지만, 그걸 실제 파이썬 코드로 옮기는 과정이 어려워서** AI에게 조건을 설명하고 스크립트 작성을 맡겼다.
- 교훈: 포트처럼 겉으로 보이지 않는 값은 직접 볼 수 없어도, 서버가 돌려주는 응답의 "차이"(여기서는 길이)를 관찰하면 간접적으로 알아낼 수 있다. 이런 간접 관찰 방식을 오라클(oracle)이라고 한다.

## 5. 배운 것 · 다음에 비슷한 문제를 만나면

- SSRF를 막는 **블랙리스트(특정 문자열/IP 금지)는 거의 항상 우회 방법이 있다.** 같은 주소를 가리키는 표기법이 여러 개 존재하기 때문이다 (`127.1`, 10진수 `2130706433`, 8진수 `0177.0.0.1`, 16진수 `0x7f000001`, IPv6 루프백 `::1` 등).
- 겉으로 드러나지 않는 값(포트, 파일명 등)은 "성공/실패에 따라 응답이 달라지는 지점"을 찾으면 브루트포스나 오라클 기법으로 추론할 수 있다.
- 개념을 안다고 바로 코드가 나오는 건 아니다. **"무엇을, 왜 해야 하는지"를 스스로 설계한 뒤 구현 도구로 AI를 쓰는 것**과 "무엇을 해야 하는지조차 AI에게 묻는 것"은 분명히 다르다. 이번에는 전자였다.

## 6. 대응 방안 (시큐어 코딩)

### 1) 근본 대응 — 블랙리스트 대신 화이트리스트 + DNS 해석 후 IP 검증

블랙리스트는 "같은 주소를 표현하는 방법이 무한히 많다"는 근본적인 약점이 있다. OWASP도 SSRF를 "deny list(블랙리스트)나 정규식으로 막지 말라"고 권고한다. 대신:

- 허용할 호스트/도메인을 화이트리스트로 명시하고, 그 외는 전부 차단한다.
- 사용자가 입력한 호스트명을 실제로 DNS 해석(resolve)한 뒤, **그 결과 IP**가 사설 대역(127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 등)인지 검사한다. 문자열 비교가 아니라 실제 IP 값으로 비교해야 `127.1` 같은 표기법 우회를 막을 수 있다.

```python
import socket
import ipaddress

def is_safe_host(hostname: str) -> bool:
    try:
        ip = socket.gethostbyname(hostname)
        addr = ipaddress.ip_address(ip)
        return not (addr.is_private or addr.is_loopback or addr.is_link_local)
    except Exception:
        return False
```

### 2) 네트워크 측면 대응

- 플래그나 민감한 자원은 외부 요청을 처리하는 웹 서버와 같은 프로세스/네트워크에 두지 않는다. (이 문제처럼 "내부에 한 번 더 서버를 띄워 로컬에서만 접근 가능하게 하는" 구조 자체를 피해야 한다.)
- URL 스키마를 `http`, `https`로 제한해 `file://`, `ftp://`, `gopher://` 등을 통한 추가 공격을 막는다.

### 3) 이 문제에 적용하면

- `"localhost" in netloc` 같은 문자열 비교를 걷어내고, 요청 직전에 실제 목적지 IP를 해석해서 루프백/사설 대역이면 무조건 차단한다.
- 내부 전용 HTTP 서버를 둬야 한다면 임의 포트로 숨기는 대신, 애초에 외부에서 들어오는 요청이 도달할 수 없는 네트워크 경계(별도 컨테이너, 방화벽 규칙 등)로 분리한다.

## 7. 핵심 키워드

- `SSRF`: 서버가 공격자가 원하는 위조된 요청을 대신 보내게 만들어, 외부에서 직접 접근할 수 없는 내부 자원에 접근하는 취약점
- `블랙리스트 우회`: 금지 문자열/표기를 그대로 쓰지 않고, 같은 대상을 가리키는 다른 표현으로 검사를 피하는 기법
- `127.1`: `127.0.0.1`과 같은 주소로 해석되는 축약 IPv4 표기 (레거시 `inet_aton` 파싱 방식)
- `오라클(Oracle)`: 직접 볼 수 없는 값을, 응답의 차이(길이, 시간 등)를 관찰해 간접적으로 알아내는 기법
- `SimpleHTTPRequestHandler`: 파이썬 내장 모듈로, 지정한 디렉터리를 그대로 HTTP로 서빙하는 간단한 서버 핸들러

## 8. 참고 자료

- 이글루코퍼레이션 보안정보, [SSRF 취약점을 이용한 공격사례 분석 및 대응방안](https://www.igloo.co.kr/security-information/ssrf-%EC%B7%A8%EC%95%BD%EC%A0%90%EC%9D%84-%EC%9D%B4%EC%9A%A9%ED%95%9C-%EA%B3%B5%EA%B2%A9%EC%82%AC%EB%A1%80-%EB%B6%84%EC%84%9D-%EB%B0%8F-%EB%8C%80%EC%9D%91%EB%B0%A9%EC%95%88/) (2022.12.06) — SSRF 정의, 공격 사례(MS Exchange, Capital One), 대응 방안 학습에 활용
- [How Do Attackers Bypass SSRF Filters? (Security Scientist)](https://answers.securityscientist.net/q/25861/how-do-attackers-bypass-ssrf-filters) — IP 표기법 우회(10진수/8진수/16진수/IPv6), OWASP의 화이트리스트 권고 확인
