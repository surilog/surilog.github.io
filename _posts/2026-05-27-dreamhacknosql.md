---
layout: single
title: "Dreamhack : Really NOT SQL 문제를 통해 보는 소스코드 뒤에 숨은 서버 설정(WebDAV)의 치명적 허점"
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


포스팅을 읽기 전, 어떤 문제인지 먼저 직접 도전해 보실 분들을 위해 아래에 드림핵 워게임 링크를 걸어두겠습니다. 

**[Dreamhack - Really NOT SQL 문제 바로가기](https://dreamhack.io/wargame/challenges/2105/)**

---

## 1. 가설 설정 : '순환 오류'와 숨은 '서버 설정'의 발견

### 1. 목표 : admin 세션 확보 및 flag구하기
{: .no_toc}

<div class="notice--success">
주어진 php 파일들을 분석해보면 flag를 희득하기 위해서는 반드시 'admin'계정의 세션이 있어야 합니다.
</div>

### 1-2. PHP 로직의 순환 오류
{: .no_toc}

관리자 권한을 얻기 위해 php 코드를 분석하던 중, 다음과 같은 논리적 교착 상태를 맞닥뜨렸습니다.


#### 1.flag.php
{: .no_toc} 

<div class="notice--success">
flag.php에 접근하기 위해서는 오직 'admin' 세션이 있어야만 가능했습니다.
</div>

#### 2. admin 로그인 조건
{: .no_toc}
<div class="notice--success">
서버에 저장된 관리자의 암호화된 패스워드와 일치해야하지만, 해싱 전의 오리지널 패스워드를 알 수 없습니다.
</div>

#### 3. edit_profile.php를 통한 비밀번호 변경 조건
{: .no_toc} 
<div class="notice--success">
아니러니하게도 비밀번호를 변경하기 위해서는 'admin'세션을 가지고 있어야 했습니다!
</div>

admin 세션에 접근 하기 위해 비밀번호를 바꾸어 접근하려고 했지만 이 기능 역시 admin 세션이 필요한 아이러니한 상황을 마주하게 되었습니다.

저는 여기서 어떻게 하면 **순환 오류**를 우회해서 비밀번호를 바꾸어 세션을 얻을 수 있을까만 생각했던 것 같습니다.

다시 생각해보면 edit_profile.php 의 기능을 보고 그 기능에만 매료되었던 것 같습니다!


### 1-3. 시야 확장: "어! 서버 설정 파일? 한 번 살펴볼까?"
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

=> **<font color='Crimson'> 즉 외부에서 이 디렉터리 내의 파일 시스템에 직접 간섭할 수 있다면, 비밀번호 변경 가능! </font>**

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

사용자 디렉터리에 DAV On 설정이 활성화 되어있었습니다! 

**WebDAV**는 'Web Distributed Authoring and Versioning'의 약자로 HTTP 프로토콜을 확장하여 **<font color='Crimson'>서버의 파일을 직접(수정, 삭제,업로드) 관리</font>** 할 수 있게 해주는 프로토콜 입니다! 

**Require all granted** 로 설정이 선언되어 있어서 **<font color='Crimson'>인증받지 않은 누구나</font>**  **WebDAV** 메소드를 사용하여 **<font color='Crimson'>내부 파일을 조작</font>**  가능하게 합니다!

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

<div class="notice--success">  
공격 페이로드를 구상하기 전, 가설의 유효성을 안전하게 검증하기 위해 **GitHub Codespaces** 로컬 개발 환경을 구축하여 테스트를 진행했습니다. 
</div>

비밀번호를 변경하는 것이 아닌 비밀번호 검증 명부 자체를 바꿔치기하는 파일 시스템 직접조작 시나리오를 구상했습니다.

즉 **<font color='Lime'>password를 바꿔치기 하는 것이 아닌 admin.json 자체를 바꿔치기하는 시나리오입니다!</font>**



### 3-1. 익스플로잇 메커니즘
{: .no_toc}

1. 스크립트로 삽입 할 admin.json의 규격을 구상했습니다.
2. HTTP의 PUT 메소드를 이용하여 서버의 /user/admin.json 파일에 덮어쓰기 요청을 보내고자 했습니다!
3. 덮어쓰기가 완료되면 로그인후 세션 희득!


## 4. 대응방안 : 인프라 보안설정 Suri

### 4-1. WebDAV 비활성화 또는 전면 차단
{: .no_toc}

원격 파일 관리가 필요 없을시에는 전면 차단 시켜주었습니다!

```Apache
<Directory /var/www/html/user/>
      # DAV On 구문 삭제 또는 명시적 Off 처리
      DAV Off
      AllowOverride None
      Require all granted
</Directory>
```

### 4-2. 특정 HTTP 메소드 통제 및 인증 강화
{: .no_toc}

서비스 운영상 사용해야한다면, <font color='Lime'>내부 사용자만 사용</font> 할 수 있도록 설정했습니다.

```Apache
<Directory /var/www/html/user/>
      DAV On
      <Limit PUT POST Background DELETE MOVE COPY>
            # 인증된 관리자 그룹 외에는 모든 접근을 거부
            Require user authorized_admin
      </Limit>
</Directory>
```

## 5. 마치며

이번 Really NOT SQL 문제는 소스코드 수준에서 아무리 철저하게 세션을 검증하고 보안 로직을 짜두었더라도, <font color='Crimson'>웹 서버 설정</font>에 단 하나의 틈새가 있다면 전체 시스템 권한이 통째로 넘어갈 수 있음을 알려주는 좋은 문제였다고 생각합니다!

이전에 해결했던 Image Uploader 문제와 오늘의 문제였던 Really NOT SQl 문제는 제가 Web 보안 설정을 생각할 때 가장 기본적으로 확인해야 할 것이 무엇인지 알려주었습니다!


**Image Uploader**: 서버 설정을 활용해 애플리케이션의 허점(필터링 논리 연산자 오용)을 메우는 심층 방어의 예시

**Really NOT SQL**: 애플리케이션 로직은 견고했으나 서버 설정의 부주의로 우회로를 내어준 인프라 취약점의 예시

결국 완벽한 웹 보안을 달성하기 위해서는 <font color='Lime'>코드 개발</font> 단의 시야에만 매몰되지 않고, <font color='Lime'>서비스가 구동되는 시스템 환경과 아파치 같은 웹 서버</font>까지 바라보는 습관을 지녀야겠습니다!



## 피드백은 언제나 환영입니다!
{: .no_toc}
부족한 글이지만 끝까지 읽어주셔서 감사합니다. <br>
 포스팅 내용 중 잘못된 정보가 있거나, 더 효율적인 방어 대책이 있다면 언제든지 댓글을 활용해 피드백 부탁드립니다. 
 <br>여러분의 소중한 의견이 저에게는 큰 배움의 기회가 됩니다!