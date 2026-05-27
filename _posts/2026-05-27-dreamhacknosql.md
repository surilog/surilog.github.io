---
layout: single
title: "Dreamhack : Really NOT SQL — 소스코드 뒤에 숨은 서버 설정(WebDAV)의 치명적 허점"
sidebar:
    nav: "main"

tag : [dreamhack,web,웹 해킹, exploit]
categories: [wargame,webDAV,서버]
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

저는 흔히 웹 취약점을 분석할 때, PHP, Python 등 애플리케이션의 소스코드 로직을 먼저 파고듭니다.
아직 경험이 많이 부족한지 SQL 인젝션이나 파일 업로드 필터링 조건을 한 줄 한 줄 검증하는 것을 정석 처럼 여기기 때문입니다.

하지만 이번 문제를 통해 저는 한 단계 성장해 나가 수 있었습니다.
왜냐하면 **웹 서버 자체의 환결 설정**의 허점에 대해 공부 할 수 있었기 때문입니다!
오늘은 Dreamhack의 **Really NOT SQL** 문제를 통해, 애플리케이션 단의 소스코드 로직이 아닌 웹 서버의 확장 프로토콜인 **<font color='Crimson'>WebDAV 설정 오류</font>**의 허점에 대해 소개해 보려고 합니다.

---

## 1. 가설 설정 : '순환 오류'와 숨은 '서버 설정'의 발견

### 1. 목표 : admin 세션 확보 및 flag구하기
{: .no_toc}

<div class="notice--success">
주어진 php 파일들을 분석해보면 flag를 희득하기 위해서는 반드시 'admin'계정의 세션이 있어야 합니다.
</div>

### 1-2. PHP 로직의 순환 오류(Paradox)
{: .no_toc}

관리자 권한을 얻기 위해 php 코드를 분석하던 중, 다음과 같은 논리적 교착 상태를 맞닥뜨렸습니다.
<div class="notice--success">
1. <h4>flag.php</h4>{: .no_toc} 에 접근하기 위해서는 오직 'admin' 세션이 있어야만 가능했습니다.
2. <h4>admin 로그인 조건</h4>{: .no_toc}: 서버에 저장된 관리자의 암호화된 패스워드와 일치해야하지만, 해싱 전의 오리지널 패스워드를 알 수 없습니다.
3. <h4>edit_profile.php를 통한 비밀번호 변경 조건</h4>{: .no_toc}: 아니러니하게도 비밀번호를 변경하기 위해서는 'admin'세션을 가지고 있어야 했습니다!
</div>

admin 세션에 접근 하기 위해 비밀번호를 바꾸어 접근하려고 했지만 이 기능 역시 admin 세션이 필요한 아이러니한 상황을 마주하게 되었습니다.
저는 여기서 어떻게 하면 **순환 오류**를 우회해서 비밀번호를 바꾸어 세션을 얻을 수 있을까에만 생각했던 것 같습니다.
다시 생각해보면 edit_profile.php 의 기능을 보고 그 기능에만 매료되었던 것 같습니다!


### 1-3. 시야 확장: "어! 서버 설정 파일들이 있네"
{: .no_toc}

웹 애플리케이션에서 생각이 잘 나지 않아, 주어진 파일들을 모두 열어보았습니다.
이때 서버 설정 파일인 **"000-default.conf"**파일을 확인 하였고 문제의 핵심을 찾을 수 있었습니다.

---

## 2. 주요 코드 및 서버 설정 분석

서버가 사용자 데이터를 처리하는 방식과 아파치(Apache) 설정 파일을 대조하며 취약점의 연결고리를 분석했습니다.

### 2-1. 애플리케이션 데이터 관리 방식 (`login.php`) 
{: .no_toc}

```php
$userDir = __DIR__ . '/user/';  # 데이터 저장 경로: /var/www/html/user/
$filename = $username . '.json'; 
$filepath = $userDir . $filename; 

$userData = json_decode(file_get_contents($filepath), true);
```

별도의 SQL 데이터베이스를 사용하지 않고, 사용자의 id와 비밀번호를 /user/디렉터리 내부에 JSON 형태의 파일(admin.json)로 저장하여 관리하고 있습니다.
=> 즉 외부에서 이 디렉터리 내의 파일 시스템에 직접 간섭할 수 있다면, 비밀번호 변경 가능!

### 2-2. 아피치 전역 및 지역 설정의 허점 (`000-default.conf`) 
{: .no_toc}
```Apache
# 루트 디렉터리 설정 (안전)
<Directory /var/www/html/>
     AllowOverride None
     Require all granted
</Directory>

# 사용자 데이터 디렉터리 설정 (위험!)
<Directory /var/www/html/user/>
      DAV On
      Options Indexes
      AllowOverride All
      Require all granted
</Directory>
```

-사용자 디렉터리에 DAV On 설정이 활성화 되어있었습니다! 
-**WebDAV**는 'Web Distributed Authoring and Versioning'의 약자로 HTTP 프로토콜을 확장하여 **<font color='Crimson'>서버의 파일을 직접(수정, 삭제,업로드) 관리</font>** 할 수 있게 해주는 프로토콜 입니다! 
-**Require all granted** 로 설정이 선언되어 있어서 **<font color='Crimson'>인증받지 않은 누구나</font>**  **WebDAV** 메소드를 사용하여 **<font color='Crimson'>내부 파일을 조작</font>**  가능하게 합니다!

### 2-3. .htaccess를 통한 제한 상황 확인  
{: .no_toc}
```Apache
<Limit DELETE>
        Require all denied
</Limit>
```

공격자가 DELETE 메소드를 사용해 파일을 무단으로 삭제 시키는 것을 막아두었습니다.
하지만 **PUT**, MOVE등 다른 메소드들은 사용 가능합니다!

## 3. 공격 페이로드 설계 : 애플리케이션단에서 안되면 서버로!

