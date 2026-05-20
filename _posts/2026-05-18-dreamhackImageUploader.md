---
layout: single
title: "Dreamhack : Image Uploader 문제를 통해 보는 파일 시그니처 분석의 중요성!
sidebar:
    nav: "main"

tag : [dreamhack,web,웹 해킹, exploit]
categories: [wargame, shell]
toc : true
toc_sticky: true
toc_label: "Contents"
author_profile: true
search: true
comments: true
published: false
---

##  Dreamhack : Image Uploader 문제를 통해 보는 파일 시그니처 분석의 중요성!

<div class="notice--success">  
본 포스팅은 드림핵의 가이드라인을 준수하여 작성되었습니다. 전체 익스플로잇 스크립트나 FLAG 값은 포함하지 않으며, 취약점의 원리 분석과 방어 대책에 집중합니다.
</div>

많은 개발자들이 사이트에서 파일 업로드 기능을 구현할 때, 악성 스크립트 실행을 막기 위해 확장자 검증뿐만 아니라 파일 내부 데이터를 검사하는 **MIME 타입 검증**을 추가하곤 합니다. "컴퓨터가 파일 내부를 직접 읽어서 판별하니까 안전하겠지?"라는 신뢰 때문입니다.

하지만 과연 안전하다고 생각하십니까? 오늘은 Dreamhack의 **Image Uploader** 문제를 통해, 서버가 파일 형식을 판별하는 메커니즘의 허점을 파고드는 공격을 분석해 보려고 합니다. 이를 통해 **파일 시그니처(Magic Number) 분석이 보안에서 왜 그토록 중요한지** 에 대한 이유를 소개하려고 합니다.

## 1. Image Uploader 가설 설정 : 역추적을 통한 공격 설계

### 1. 목표 : flag구하기
{: .no_toc}

<div class="notice--success">
 코드 상에서는 flag가 어디에 위치하는지 안 보입니다.
</div>

### 2. flag를 어디서 구할 수 있는지 찾기
{: .no_toc}

<div class="notice--success">
단서: 파일을 업로드 할 수 있다!
</div>

### 3. 파일 업로드 취약점이 가능한지 확인
{: .no_toc}

<div class="notice--success">
조건: Directory Traversal 공격 가능한지 확인
</div>

### 3-1. Directory Traversl 공격 구문 유효?
{: .no_toc}

<div class="notice--success">
조건: 스크립트 업로드
</div>

### 4. 안 되면 다른 취약점 찾기
{: .no_toc}

<div class="notice--success">
조건: 뭐가 있을까...?
</div>


## 2.취약점 코드 분석 : 논리 연산자(&&)의 함정!

```python

if (!in_array($mime_type, $allowed_mimes) && !in_array($check_extension, $allowed_extensions)) { 
    #확장자와 MIME둘다 틀릴 경우 차단 => 하나만 맞아도 업로드 가능
        die("<script>alert('Only images allowed.'); history.back();</script>");
    }

```
여기서 치명적인 보안사고가 발생합니다.

서버는 화이트리스트 방식으로 허용된 확장자($allowed_extensions)와 MIME 타입($allowed_mimes)을 검사하지만, 조건문이 && (AND) 연산자로 묶여 있습니다.
즉, MIME 타입도 이미지가 아니고, 동시에 확장자도 이미지가 아닐 때만 업로드를 차단합니다. 
다시 말해서 둘 중 하나만 이미지 조건을 만족하면 필터링을 우회하여 파일 업로드가 가능하다는 의미가 됩니다!


## 3. 파일 시그니처 조작 원리

드디어 이번 포스팅의 주제인 **파일 시그니처 조작 원리**에 대해 소개하려고 합니다.

### 3-1파일 시그니처란


   먼저 파일 시그니처가 무엇인지 간단하게 소개 하겠습니다.
   ●파일 시그니처는 파일의 내부 형식을 식별할 수 있게 해주는 **<font color='Crimson'>고유한 바이트 패턴</font>**입니다.

### 3-2 파일 시그니처 구분


   #### 1. 헤더 시그니처(Header Signature)
    {: .no_toc}

 **<font color='Crimson'> 파일의 가장 첫 부분 </font>** (보통 0~10바이트 이내)에 위치하는 바이트 패턴 값
      -운영체제나 분석 도구가 **<font color='Crimson'>파일 형식을 인식할 때 가장 먼저 참고</font>**하는 부분
      -이 파일이  **<font color='Crimson'>특정한 확장자 명을 가졌다는 것을 알려주는 hex값!</font>** 입니다.

   #### 2. 이미지 데이터(Header Signature)
{: .no_toc}
       -헤더~푸터 시그니처 사이에 존재하는 hex 값으로, **<font color='Crimson'>실제 파일을 구성하는 정보!</font>**

   #### 3. 푸터 시그니처(Footer Signature)
{: .no_toc}
      -파일의 **<font color='Crimson'> 가장 마지막 부분에 위치하는 바이트 패턴 값</font>**(흔히 Tralier라고 부릅니다.)

 ex. PNG 파일은 시작 시그니처: 89 50 4E 47 0D 0A 1A 0A 를 가지며 푸터 시그니처로 49 45 4E 44 AE 42 60 82 를 가집니다.

### 3-3 파일 시그니처의 중요성
<div class="notice--success">
-단순히 파일의 이름이나, 확장자가 .jpg, .pdf로 되어 있다 해서, 그 파일이 실제도 해당 포맷이라 보장할 수 없습니다!
-시그니처가 다르면 파일이 정상적으로 열리지 않거나 오류가 발생 가능하고 악성코드(웹쉘)가 위장 되어 있을 수 있습니다!
</div>

### 3-4 서버(finfo_file)의 MIME 타입 판별 메커니즘
소스코드에서 사용된 PHP의 finfo_file() 함수는 파일의 MIME 타입을 판별할 때 리눅스 표준인 libmagic 데이터베이스를 참조합니다!

**[PHP 공식 문서](https://www.php.net/manual/en/book.fileinfo.php "finfo_file()함수 설명")**에선 finfo_file() 함수를 다음과 같이 정의하고 있습니다.

 <div class="notice--success">
The functions in this module try to guess the content type and encoding of a file by looking for certain magic byte sequences at specific positions within the file. While this is not a bullet proof approach the heuristics used do a very good job.</div>
즉, 서버는 성능과 속도(효율성)을 위해 대용량 파일 전체를 검사하는 것이 아니라, 오직 특정 매직 바이트만 읽은 뒤 MIME 타입을 최종 라벨링 합니다!

## 4. 공격 페이로드 구상: 파일 시그니처 조작

위 취약점을 활용해 저는 확장자와 MIME 타입 중 하나만 이미지로 속여서 서버를 통과시키는 전략을 세웠습니다.
본론에 들어가기에 앞서, 보다 안전하고 정확한 검증을 위해 **GitHub Codespaces** 환경을 활용하여 로컬 서버에서 사전 실습 및 테스트를 진행했습니다.

우선 명령어 스크립트를 실행 시키려면 확장자는 반드시 **.php** 여야 합니다.
이 경우 확장자 화이트리스트 검증은 실패하게 되므로, 파일 업로드를 성공 시키기 위해선 **MIME 타입 검증만큼은 무조건 조건에 부합되도록 참으로 우회**시켜야 합니다.

#### 웹 셀가능한지 확인
{: .no_toc}

```php
GIF89a
<?php system('ls -al', $return_var); ?>
```
GIF89a는 GIF 이미지 파일의 고유한 매직 넘버입니다!
ls -al명령어를 통해 현재 위치의 디렉터리에 있는 파일을 볼 수 있는지 시스템 명령어를 넣어줬습니다.



<div style="text-align: center; margin: 20px 0;">
  <img src="{{ '/images/imageuploader/success.png' | relative_url }}"
       alt="이미지 업로드 성공"
       style="max-width: 80%; height: auto; border: 1px solid #ddd; border-radius: 5px;">
  <p style="font-size: 0.9em; color: #ffffff;">[필터링 우회 성공]</p>
</div>

구상한 페이로드를 담아 확장자가 .php인 파일로 업로드를 시도한 결과, 예상대로 서버는 확장자 검증에는 실패했지만 파일 앞의 GIF 매직넘버인 GIF89a 덕분에 MIME 타입 검증을 정상으로 인식하여 성공적으로 업로드를 하였습니다!

<div style="text-align: center; margin: 20px 0;">
  <img src="{{ '/images/imageuploader/flag.png' | relative_url }}"
       alt="시그니처 조작"
       style="max-width: 80%; height: auto; border: 1px solid #ddd; border-radius: 5px;">
  <p style="font-size: 0.9em; color: #ffffff;">[파일 시그니처 조작 성공]</p>
</div>
이후 서버가 재정의한 파일 경로를 찾아 웹에서 해당 파일에 직접 접근했습니다.
웹 서버는 확장자(.php)를 기준으로 PHP엔진에게 처리를 넘겼고, PHP엔진은 맨 첫 줄의 GIF89a 뒤 진짜 코드를 실행했습니다!
그 결과 웹 공간에서 서버 측 제어권을 희득하는 원격 코드 실행이 가능한 것을 확인했으며, 디렉터리 경로 조작을 통해 시스템 내부에 숨겨져 있던 최종 목적지를 파악 할 수 있었습니다!



## 5 대응 방안: Suri code

### 5-1 : 논리 연산자 수정 및 개별 검증
확장자와 MIME타입을 검사할 때 사용되는 &&(and)연산자를 **||(OR)연산자로 변경**하거나, **각각 독립된 if문으로 분리**하여 둘 중 하나라도 화이트리스트 규칙을 만족하지 못하면 무조건 업로드를 차단하도록 **로직의 Suri**가 필요합니다!

다음은 Suri된 로직을 Github codespaces 환경을 활용하여 로컬 서버에서 테스트한 결과입니다.
```python
if (!in_array($mime_type, $allowed_mimes) ) { # mime타입 먼저 검사
        die("<script>alert('MIME 타입이 올바르지 않습니다.'); history.back();</script>");
    }
     if (!in_array($file_extension, $allowed_extensions) ) { #확장자 따로 검사
        die("<script>alert('허용되지 않은 확장자입니다.'); history.back();</script>");
    }

```
<div style="text-align: center; margin: 20px 0;">
  <img src="{{ '/images/imageuploader/flag.png' | relative_url }}"
       alt="이중 검증"
       style="max-width: 80%; height: auto; border: 1px solid #ddd; border-radius: 5px;">
  <p style="font-size: 0.9em; color: #ffffff;">[이중 검증 성공!]</p>
</div>

이렇게 **개별 검증 패턴**으로 로직을 분리하여 확장자가 .php이거나 MIME 타입이 조작된 그 어떤 파일이 들어오더라도 각각의 방어벽에 가로막혀 업로드가 원천 차단된 것을 확인 할 수 있습니다!


### 5-2 : 업로드 디렉터리의 웹 스크립트 실행 권한 제거

소스코드를 수정하는 것 외에도, 웹 서버 환경에서 2중 방어벽을 세우는 '심층 방어'에 대해서도 이야기 해보려고 합니다.
심층 방어를 활용하게 되면 공격자가 어떤 우회 기법을 써서 악성 PHP 파일을 `uploads/` 폴더에 업로드하는 데 성공하더라도, **그 폴더 안에서 스크립트 엔진이 실행되지 않도록 차단**하면 원격 코드 실행(RCE)을 원천 봉쇄할 수 있습니다.

웹 서버 환경에 따라 아래와 같이 설정을 추가하여 업로드 폴더의 실행 권한을 제거할 수 있습니다.

* **Apache 웹 서버 (`.htaccess` 활용):**
  `uploads/` 디렉터리 내에 `.htaccess` 파일을 생성하고 아래 설정을 추가하여 PHP 스크립트 핸들러를 무력화합니다.
  ```apache
  <FilesMatch "\.(php|php3|php4|php5|phtml|phps)$">
      Order Allow,Deny
      Deny from all
  </FilesMatch>

#### 연계 분석 : 소스코드보다 강력한 '서버 설정'의 중요성
{: .no_toc}


사실 제가 파일 업로드 기능의 서버 환경 설정을 방어 대책으로 강조하는 이유는, 최근 드림핵의 **Really NOT SQL** 문제를 해결하며 서버 설정 오류가 가져오는 치명적인 위험성에 대해 공부를 했기 때문입니다.

Really NOT SQL 문제의 경우, 애플리케이션(PHP) 측면에서는 정문(Login/Edit Profile)을 지키며 세션 검증을 철저하게 수행하고 있었습니다.
하지만 다음과 같이 **서버 설정 측면**에서의 문의 suri가 필요했었습니다.

```apache
<Directory /var/www/html/user/>
      DAV On                 
      #webDAV기능 실행 
      Options Indexes
      AllowOverride All     
      #이 디렉터리의 설정을 누구나 마음대로 변경 가능 
      Require all granted        
      #누구나 접근 가능 
  </Directory>
  ```

#### 기본 서버 설정 분석
{: .no_toc}

```apache
AddType application/x-httpd-php .php .phtml .php3 .php4 .php5 .inc

Options +Indexes

<Files "*">  
    # 모든 파일에 대해 외부 접근 및 옵션 허용
    Allow from all
</Files>

<FilesMatch "\.php">
    # 확장자에 .php가 포함되어 있으면 PHP 스크립트 엔진으로 처리!
    SetHandler application/x-httpd-php
    #무조건 PHP 스크립트 엔진 핸들러로 던져서 실행하라고 서버에 명령
</FilesMatch>
```

#### GitHub Codespaces를 통한 방어 로직 검증 (실습)
{: .no_toc}


이 아파치 설정(`.htaccess`)이 실제로 악성 스크립트 실행을 완벽하게 차단하는지 확인하기 위해, 앞서 구축한 **GitHub Codespaces** 로컬 서버 환경에서 직접 테스트를 진행해 보았습니다.

#####  환경 구성: 기존 .htaccess파일 내용 수정
{: .no_toc}
기존 파일에 선언되어 있던 위험한 접근 허용 구문을 지우고, 다음과 같이 **특정 확장자의 접근 및 실행을 원천 차단하는 방어 구문**으로 수정했습니다.

```Apache
# 전역/기본 설정 (그대로 유지)
AddType application/x-httpd-php .php .phtml .php3 .php4 .php5 .inc
Options +Indexes

# 추가 된 하위 디렉터리 통제 구문 
<FilesMatch "\.(php|php3|php4|php5|phtml|phps)$">
    Order Allow,Deny
    Deny from all
</FilesMatch>
```
이렇게 구성하면 AddType 지시어로 인해 PHP 확장자들이 정의되더라도, 하단의 **FilesMatch** 블록이 해당 확장자를 가지면 우회 업로드한 스크립트 엔진이 실행 되지 않도록 막아 줄 수 있습니다!


<div style="text-align: center; margin: 20px 0;">
  <img src="{{ '/images/imageuploader/server.png' | relative_url }}"
       alt="심층 방어"
       style="max-width: 80%; height: auto; border: 1px solid #ddd; border-radius: 5px;">
  <p style="font-size: 0.9em; color: #ffffff;">[서버를 활용한 심층 방어 성공!]</p>
</div>


  **(서버 설정의 취약점을 깊게 파고들었던 Really NOT SQL 문제의 상세한 분석과 익스플로잇 가설 설정 과정은 추후 포스팅에서 단독으로 자세히 다루어 보도록 하겠습니다!)**

## 6. 마치며 : 파일 시그니처 분석이 남긴 교훈
이번 Dreamhack Image Uploader 문제는 단순한 필터링 코드 한 줄, 혹은 논리 연산자 하나를 잘못 선택하는 것이 시스템 전체의 권한을 넘겨주는 치명적인 독이 될 수 있음을 잘 보여주는 좋은 예시였습니다.

특히 컴퓨터가 파일 형식을 판별할 때 성능 효율성을 위해 '특정 위치의 고유 매직 바이트 시퀀스'만 검사한다는 로우레벨 메커니즘을 정확히 이해하고 있어야만, 이러한 교묘한 우회 공격을 진단하고 완벽하게 방어할 수 있다는 점에서 기본기(Fundamental)의 중요성을 깊게 체감할 수 있었던 유익한 실습이었습니다.

앞으로도 보안을 공부할 때는 항상 코드에만 매몰되지 않고, 시스템과 웹 서버 환경까지 넓게 바라보는 시야를 가져야겠습니다.