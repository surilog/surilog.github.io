---
layout: single
title: '[Dreamhack] 새롭게 바뀐 sesstion_basic 풀이 및 분석'
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
본 포스팅은 Dreamhack의 새롭게 바뀐 sesstion_basic워게임 문제를 분석한 기록입니다. (드림핵 가이드라인을 준수하여 FLAG 직접 노출은 지양하고 핵심 분석 위주로 정리했습니다.)
</div>


# [Dreamhack] session-basic

- 날짜: 2026-11-12
- 분야: 웹해킹
- 도움 받은 정도: 1단계 · 혼자 고민하기 (AI 도움 없음)

## 1. 개요 및 핵심 요약

Flask 세션 기반 로그인 서비스에서, `/admin` 라우터의 인증 체크가 주석 처리되어 있어 **서버가 가진 전체 세션 저장소(`session_storage`)를 누구나 그대로 열람**할 수 있는 문제다. 그 안에 담긴 admin의 세션 ID 값을 그대로 내 쿠키의 `sessionid` 값으로 덮어써서, 인증 없이 admin으로 위장해 플래그를 획득했다.

## 2. THINK · 분석

- 파이썬 Flask로 만든 로그인 서비스이고, 로그인 성공 시 서버가 무작위 세션 ID를 발급해 쿠키(`sessionid`)로 내려준다.

```python
@app.route('/admin')
def admin():
    # developer's note: review below commented code and uncomment it (TODO)

    #session_id = request.cookies.get('sessionid', None)
    #username = session_storage[session_id]
    #if username != 'admin':
    #    return render_template('index.html')

    return session_storage
```

- **취약점의 근본 원인(Root Cause)**: `/admin` 라우터는 본래 "로그인한 사람이 admin인지"를 확인하는 코드가 있어야 하는데, 그 코드가 전부 주석 처리되어 있다. 그래서 인증 여부와 상관없이 **서버의 세션 저장소(`session_storage`) 전체를 그대로 응답으로 돌려준다.**
- `session_storage`는 `{세션ID: 유저이름}` 형태의 딕셔너리이고, 서버가 시작할 때 이미 admin의 세션을 미리 만들어 놓는다.

```python
if __name__ == '__main__':
    import os
    session_storage[os.urandom(32).hex()] = 'admin'
    print(session_storage)
    app.run(host='0.0.0.0', port=8000)
```

  admin의 세션 ID는 `os.urandom(32).hex()`로 만들어져 있어 **직접 추측(브루트포스)하는 건 사실상 불가능**하지만(소스 주석에도 "cannot reveal admin's sessionid by brute forcing"이라고 쓰여 있다), `/admin`이 그 값을 그냥 보여주고 있으니 추측할 필요가 없다.
- 메인 페이지(`/`)는 내 쿠키의 `sessionid`가 `session_storage`에서 가리키는 username이 `'admin'`일 때만 플래그를 보여준다.

```python
@app.route('/')
def index():
    session_id = request.cookies.get('sessionid', None)
    try:
        username = session_storage[session_id]
    except KeyError:
        return render_template('index.html')
    return render_template('index.html', text=f'Hello {username}, {"flag is " + FLAG if username == "admin" else "you are not admin"}')
```

- **세션 하이재킹(Session Hijacking)**: 공격자가 다른 사용자의 세션 ID를 알아내 자신의 요청에 그대로 사용함으로써, 로그인 절차 없이 그 사용자로 위장하는 공격이다. 보통은 세션 ID를 훔치기 위해 XSS로 쿠키를 탈취하거나, 추측 가능한 ID를 브루트포스하는 식으로 이루어지는데, 이 문제에서는 **서버가 직접 노출해 준 값을 가져다 쓰기만 하면 돼서** 별도의 공격 스크립트조차 필요 없었다.

## 3. CREATE · 설계

1. **인증되지 않은 정보 노출 지점 찾기**: `/admin`에 인증 체크가 없다는 걸 소스에서 확인했으니, 로그인하지 않은 상태로 `/admin`에 접속해 `session_storage` 전체를 받아올 수 있다.
2. **admin의 세션 ID 추출**: 받아온 딕셔너리에서 값이 `"admin"`인 키(=세션 ID)를 찾는다.
3. **세션 쿠키 덮어쓰기**: 내 브라우저의 `sessionid` 쿠키 값을 admin의 세션 ID로 **교체**하고 `/`로 이동하면, 서버 입장에서는 admin이 요청한 것과 구분이 안 되므로 플래그를 내려준다.

## 4. SOLVE · 검증

**1) `/admin`에서 admin 세션 ID 확인**

![/admin 라우터에서 전체 session_storage를 확인한 화면](images/sesstion_basic/session-basic-01-admin-route.png)

- 로그인하지 않은 상태로 `/admin`에 접속하면 서버의 `session_storage` 딕셔너리 전체가 JSON으로 그대로 노출된다.
- 그중 `"...e925e5b7": "admin"`으로 되어 있는 키가 admin의 세션 ID다.

**2) guest로 로그인해 쿠키 구조 확인**

![guest로 로그인한 뒤 sessionid 쿠키를 확인한 화면](images/session-basic-02-guest-login.png)

- `guest/guest`로 로그인한 뒤 개발자 도구 → 애플리케이션 → 쿠키에서 `sessionid`라는 이름으로 세션이 저장되는 걸 확인했다. "아직 admin이 아니다"라는 응답도 함께 확인했다.

**3) 쿠키 값을 admin 세션 ID로 교체**

![sessionid 쿠키를 admin 값으로 바꾼 뒤 플래그를 획득한 화면](images/session-basic-03-flag.png)

- 기존 `sessionid` 쿠키의 값을 1)에서 확인한 admin 세션 ID로 **덮어쓰고** `/`로 다시 접속하니 `Hello admin, flag is ...`가 출력됐다.

**4) 시행착오**

- 처음에 개발자 도구에서 쿠키를 고칠 때, 기존 `sessionid` 행의 값을 바꾼 게 아니라 **새로운 행을 추가**해버렸다. 그 결과 같은 이름의 쿠키가 둘 생기면서 서버가 기대한 대로 동작하지 않아 admin으로 인식되지 않았다.
- 원인을 다시 생각해보니, 쿠키를 바꿀 때는 **기존 행을 선택해서 값(Value)만 수정**해야 하고, 빈 행에 새로 이름과 값을 입력하면 별개의 항목으로 추가된다는 걸 알게 됐다. 이후 기존 `sessionid` 행의 값만 교체하니 정상적으로 admin으로 인식됐다.
- 교훈: 개발자 도구로 쿠키를 조작할 때는 "추가"와 "수정"이 다른 동작이라는 점을 주의해야 한다.

## 5. 배운 것 · 다음에 비슷한 문제를 만나면

- 세션 ID 자체는 `os.urandom(32).hex()`처럼 충분히 무작위라도, **그 값을 보여주는 다른 경로(로직 결함, 디버그 엔드포인트 등)가 있으면 추측 난이도는 의미가 없어진다.** "값이 안전한가"뿐 아니라 "그 값이 새어 나갈 길이 없는가"도 함께 봐야 한다.
- 인증 체크 코드가 주석 처리되어 있거나 TODO로 남아 있는 부분은 실제 서비스에서도 흔히 발생하는 실수이니, 코드 리뷰에서 반드시 짚어야 할 지점이다.
- 이번엔 세션 하이재킹 단계까지만 다뤘고, 세션 ID를 직접 얻을 수 없는 상황(XSS로 쿠키 탈취, 세션 고정 공격 등)은 아직 다뤄보지 않았다. 다음에 비슷한 문제를 만나면 "세션 ID를 어떻게 훔치는가"까지 더 살펴볼 필요가 있다.

## 6. 대응 방안 (시큐어 코딩)

### 1) 근본 대응 — 인증 체크 코드 복구

가장 직접적인 원인은 `/admin`의 인증 로직이 통째로 주석 처리된 것이다. 주석을 해제하기만 해도 이 문제는 막힌다.

```python
@app.route('/admin')
def admin():
    session_id = request.cookies.get('sessionid', None)
    username = session_storage.get(session_id)
    if username != 'admin':
        return render_template('index.html')
    return session_storage  # 그래도 전체 세션을 그대로 보여주는 건 여전히 위험하다
```

다만 인증을 통과한 뒤에도 `session_storage` 전체(다른 사용자들의 세션 ID까지)를 그대로 노출하는 건 추가 위험이므로, admin 전용 화면이라도 필요한 정보만 가공해서 보여줘야 한다.

### 2) 세션 관리 자체의 보완

- 쿠키에 `HttpOnly`, `Secure`, `SameSite` 속성을 설정해 자바스크립트로 쿠키를 읽거나, HTTPS가 아닌 경로로 쿠키가 전송되는 걸 막는다.
- 로그인 성공 시마다 세션 ID를 새로 발급해(세션 고정 공격 방지), 로그아웃 시에는 쿠키 삭제뿐 아니라 서버 쪽 `session_storage`에서도 실제로 제거한다.
- 세션에 타임아웃을 둬서 일정 시간 뒤에는 자동으로 만료시킨다.

### 3) 이 문제에 적용하면

- `/admin`의 주석을 해제해 인증 체크를 살리고, 응답도 `session_storage` 전체가 아니라 필요한 정보만 돌려주도록 바꾼다.

## 7. 핵심 키워드

- `세션(Session)`: 상태가 없는 HTTP에서 로그인 상태를 유지하기 위해 서버가 관리하는 사용자별 정보. 클라이언트에는 그 정보를 찾아갈 세션 ID만 쿠키로 내려준다.
- `세션 하이재킹(Session Hijacking)`: 다른 사용자의 세션 ID를 알아내 그대로 사용해, 로그인 절차 없이 그 사용자로 위장하는 공격
- `인증되지 않은 정보 노출`: 로그인 여부를 확인하지 않고 민감한 데이터(여기서는 전체 세션 저장소)를 그대로 응답에 담아 버리는 결함
- `HttpOnly` / `Secure` / `SameSite`: 쿠키 탈취·전송 경로를 제한해 세션 하이재킹을 어렵게 만드는 쿠키 속성들

## 8. 참고 자료

- IT위키, [세션 관리](https://itwiki.kr/w/세션_관리) — 세션 ID의 역할, 세션 ID 추측 방지, HttpOnly/Secure/SameSite 등 대응 방안 확인
