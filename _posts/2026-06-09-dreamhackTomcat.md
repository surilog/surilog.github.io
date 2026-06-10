---
layout: single
title: "dreamhack Tomcat Manager : Path Traversal 및 웹쉘 업로드를 통한 RCE 분석"
sidebar:
    nav: "main"
tag : [dreamhack, web, 웹 해킹, exploit, path-traversal, tomcat]
categories: [wargame, 보안]
toc : true
toc_sticky: true
toc_label: "Contents"
author_profile: true
search: true
comments: true
published: false
---

Tomcat 서버 환경에서 소스 코드 검증 미흡으로 발생하는 <font color='#f7356f'>경로 조작 취약점은</font>, 단순한 파일 노출을 넘어 서버 전체의 제어권을 넘겨주는 치명적인 공격 체인의 시발점이 될 수 있습니다.

오늘은 Dreamhack의 **Tomcat Manager** 문제를 통해 **Path Traversal(경로 조작) 취약점**의 원리를 이해하고, 이를 통해 어떻게 관리자 권한까지 빌드업하여 최종 익스플로잇에 성공할 수 있는지 그 과정을 소개해 보려고 합니다.

> **Dreamhack - Tomcat Manager 문제 바로가기**
> [드림핵 공식 워게임 챌린지 링크](https://dreamhack.io/wargame/challenges/248)

<div class="notice--success">
본 포스팅은 드림핵 가이드라인을 준수하여 FLAG 값이나 최종 익스플로잇 자동화 스크립트는 포함하지 않습니다.
</div>

---

## 1. 가설 설정: '경로 제한'과 '서버 설정'의 역추적

문제를 해결하기 위해 제공된 파일과 파일 다운로드 로직을 분석하며 다음과 같이 공격 가설을 수립했습니다.

### (1) 최종 목표 설정
{: .no_toc}
문제 설명에 따르면 최종 플래그는 `/flag` 경로에 존재합니다. 최종 목표는 이 경로에 접근하여 내부 데이터를 읽어내는 것입니다.

### (2) 제공 파일 분석 (Root.war)
{: .no_toc}
웹 애플리케이션 아카이브인 `.war` 파일은 웹 서비스를 구성하는 소스 코드와 설정 파일이 하나로 묶여 있는 압축 파일입니다. <br>확장자를 **`.zip`**으로 변경하면 내부 소스코드를 디컴파일하여 정적 분석을 진행할 수 있습니다.

### (3) 소스 코드 취약점 발견 (image.jsp)
{: .no_toc}
압축을 해제한 뒤 `image.jsp` 파일을 분석한 결과, 사용자가 입력한 파일 경로 파라미터 값을 별다른 필터링이나 검증 없이 그대로 받아들여 스트림으로 읽어온다는 사실을 확인했습니다. 즉, **Path Traversal(경로 조작)** 통로가 열려 있음을 의미합니다.

---

## 2. 익스플로잇 전개: 관리자 로그인 빌드업

가설을 기반으로 `/flag` 경로를 직접 찾고자 시도해 보았으나, 웹 루트 상위(`../../`)로 아무리 이동해도 플래그 파일에 접근할 수 없었습니다. <br>애플리케이션 구조상 파일 시스템 접근에 한계가 있거나 경로 깊이가 맞지 않는 상황이었습니다.<br>
처음 문제 힌트로 주어진 tomcat-users.xml 스니펫 파일에서는 계정의 ID만 확인이 가능하고 비밀번호는 가려져 공백이나 무차별 대입으로도 한계가 있는 상황이었습니다.<br>

이에 따라 방향을 전환하여, 실제 서버 내부에 구동 중인 <font color='#4ADE80'> 진짜 tomcat-users.xml 경로로 접근해 주석이나 설정에 숨겨진 실제 PW를 알아내 매니저 페이지로 로그인</font>하는 전략을 구상했습니다.

### (1) 표준 경로 추적 및 인증 파일 확인
{: .no_toc}
아파치 톰캣의 표준 디렉터리 구조상, <font color='#4ADE80'>사용자 자격 증명 정보가 담긴 `tomcat-users.xml` 파일은 보통 메인 설정 폴더인 `conf/` 경로 안에 존재</font>합니다.<br> 취약점이 존재하는 이미지 요청 통로를 통해 시스템 설정 파일에 접근을 시도했습니다.

* `공격 페이로드 예시`: `https://[Target_URL]/image.jsp?file=../../../conf/tomcat-users.xml`


### (2) 브라우저 이미지 필터링 우회 (F12 활용)
{: .no_toc}
위 경로를 주소창에 입력하면 404 에러가 아니라 이미지가 깨진 '엑스박스'가 나타납니다. `image.jsp` 소스코드가 기본 응답 타입을 `image/jpeg`로 강제하고 있기 때문에, 서버는 정상적으로 XML 텍스트를 응답했으나 브라우저가 이를 이미지 파일로 해석하려다 렌더링이 깨진 현상입니다.
<div style="text-align: center; margin: 20px 0;">
  <img src="{{ '/images/TomcatManager/path.png' | relative_url }}"
       alt="깨진 이미지"
       style="max-width: 80%; height: auto; border: 1px solid #ddd; border-radius: 5px;">
  <p style="font-size: 0.9em; color: #ffffff;">[깨진 이미지]</p>
</div>
위의 사진은 이미지가 깨진 '엑스박스'가 나타난 사진입니다.

* **해결 방법**: `F12` 개발자 도구를 켜고 **네트워크(Network) 탭**으로 이동한 뒤 새로고침을 누릅니다. 해당 요청의 **Response(응답) 창**을 확인하면 브라우저 필터링에 가려져 있던 `tomcat-users.xml`의 가공되지 않은 소스코드가 투시되듯 그대로 나타납니다!<br>
Ctrl + U를 눌러도 소스코드를 확인할 수 있습니다!

<div style="text-align: center; margin: 20px 0;">
  <img src="{{ '/images/TomcatManager/pw.png' | relative_url }}"
       alt="PW확인"
       style="max-width: 80%; height: auto; border: 1px solid #ddd; border-radius: 5px;">
  <p style="font-size: 0.9em; color: #ffffff;">[숨겨진 PW]</p>
</div>
위의 사진은 경로 이동 취약점을 통해 관리자의 pw를 알아낸 사진입니다.

### (3) 관리자 자격 증명 확보 및 대시보드 장악
{: .no_toc}
탈취한 내부 XML 코드 안에서 주석 처리가 누락되어 방치된 매니저 대시보드 로그인 비밀번호(PW)를 찾아내는 데 성공했습니다. 

확보한 계정 정보를 가지고 톰캣 매니저 표준 경로인 `/manager/html`로 접속하여 정상적으로 로그인을 마쳤습니다.<br> 대시보드 내부에는 공격자가 임의의 `.war` 웹셸 파일을 업로드하여 원격 코드를 실행(RCE)할 수 있는 취약한 배포(Deploy) 섹션이 활성화되어 있었습니다.

<div style="text-align: center; margin: 20px 0;">
  <img src="{{ '/images/TomcatManager/login.png' | relative_url }}"
       alt="로그인"
       style="max-width: 80%; height: auto; border: 1px solid #ddd; border-radius: 5px;">
  <p style="font-size: 0.9em; color: #ffffff;">[로그인]</p>
</div>

<div style="text-align: center; margin: 20px 0;">
  <img src="{{ '/images/TomcatManager/web.png' | relative_url }}"
       alt="로그인"
       style="max-width: 80%; height: auto; border: 1px solid #ddd; border-radius: 5px;">
  <p style="font-size: 0.9em; color: #ffffff;">[웹쉘 업로드]</p>
</div>

.war 확장자로 웹 쉘을 업로드할 수 있습니다! 즉 RCE(원격 코드 실행)이 가능합니다.

### (4) 주요 소스 코드 분석 (`index.jsp` & `image.jsp`)
{: .no_toc}

공격 통로가 된 두 핵심 파일의 소스코드를 분석해 보면, 구조적 문제와 취약점의 원인을 명확히 파악할 수 있습니다.

#### 1. 애플리케이션의 메인 화면 (`index.jsp`)
{: .no_toc}
서비스 접속 시 처음 렌더링되는 메인 페이지의 구조입니다.

```html
<html>
<body>
    <center>
        <h2>Under Construction</h2>
        <p>Coming Soon...</p>
        <img src="./image.jsp?file=working.png"/>
    </center>
</body>
</html>

```

분석: 화면 중앙에 "공사 중(Under Construction)" 메시지와 함께 내부 이미지를 불러옵니다.<br> 
이때 이미지를 직접 출력하지 않고 image.jsp에 <font color='#f86941'>file=working.png라는 파라미터를 넘겨 간접적으로 이미지를 로드</font>하는 방식을 취하고 있습니다.

#### 2. 취약점이 존재하는 이미지 로직 (image.jsp)
{: .no_toc}
index.jsp로부터 파일 이름을 넘겨받아 서버 내부의 파일을 읽어오는 핵심 로직입니다.

<%@ page trimDirectiveWhitespaces="true" %>
<%
String filepath = getServletContext().getRealPath("resources") + "/";
String _file = request.getParameter("file");

response.setContentType("image/jpeg");
try{
    // [위험] <font color='#f86941'>사용자가 입력한 경로와 파일명을 검증 없이 스트림에 전달</font>
    java.io.FileInputStream fileInputStream = new java.io.FileInputStream(filepath + _file);
    int i;   
    while ((i = fileInputStream.read()) != -1) {  
        out.write(i);
    }   
    fileInputStream.close();
}catch(Exception e){
    response.sendError(404, "Not Found !" );
}
%>


##### 핵심 취약점 요인
{: .no_toc}

**입력값 무검증**: <font color='#f7356f'>request.getParameter("file")을 통해 외부에서 입력받은 _file 변수에 대해 어떠한 필터링(예: ../ 검사)도 수행하지 않습니다.</font>

**경로 결합 오류**: 서버의 리소스 절대 경로인 filepath와 사용자 입력값 _file을 단순 문자열 더하기(filepath + _file)로 결합합니다.<br> 이로 인해 공격자가 ../../와 같은 상위 이동 기호를 입력하면 지정된 resources 디렉터리를 벗어나 시스템 내부 폴더(예: /conf, /etc)에 임의로 접근할 수 있는 <font color='#fc5537'>Path Traversal 상태가 완성됩니다.</font>

**예외 처리 방식**: 파일 처리 중 에러가 발생하면 무조건 404 Not Found ! 에러 페이지를 반환하도록 설계되어 있어, 역으로 에러가 발생하지 않는 정상 응답(200 OK)을 통해 파일 존재 여부와 경로 깊이를 유추하는 단서가 됩니다.




## 3. 최종 익스플로잇 및 쉘 획득 (RCE)

톰캣 매니저 앱 기능을 활용하여 최종 목표인 `/flag` 파일 읽기를 완수하는 단계입니다.

### (1) WAR 웹쉘 업로드
{: .no_toc}
단순히 시스템 명령어를 실행하고 결과를 반환해 줄 수 있는 JSP 코드(웹쉘)를 작성한 뒤, 이를 `zip`으로 압축하고 확장자를 `.war`로 변경합니다.<br> 매니저 대시보드의 **"WAR file to deploy"** 섹션을 통해 이 파일을 업로드하여 서버에 배포시킵니다.

악성 도구로 악용될 소지가 있어 구체적인 공격 스크립트를 본문에 첨부하지는 않았습니다. 

사실 저도 자바(Java) 언어나 JSP 환경은 익숙하지 않아서 처음에는 스크립트 작성을 두고 다소 막막했습니다.<br> 하지만 포기하지 않고 구글링을 거듭하고 AI의 도움을 적극적으로 활용하여 다양한 예시 스크립트를 분석한 덕분에 솔루션을 구축할 수 있었습니다.<br> 구조가 생소하더라도 관련 레퍼런스를 참고하며 동작 프로세스를 차근차근 짚어보면 기본 원리를 쉽게 이해할 수 있습니다.

### (2) 원격 명령어 실행을 통한 플래그 획득
{: .no_toc}
성공적으로 배포가 완료되면 우리가 설정한 경로로 접근이 가능해집니다.<br> 웹쉘 파라미터를 통해 리눅스 명령어를 전달하여 시스템 루트에 존재하는 플래그 파일의 내용을 안전하게 획득할 수 있었습니다.


<div style="text-align: center; margin: 20px 0;">
  <img src="{{ '/images/TomcatManager/shell.png' | relative_url }}"
       alt="웹쉘 업로드"
       style="max-width: 80%; height: auto; border: 1px solid #ddd; border-radius: 5px;">
  <p style="font-size: 0.9em; color: #ffffff;">[웹쉘 업로드]</p>
</div>


## 4. 대응 방안: 안전한 인프라 및 코드 관리

### (1) 소스코드 수준의 파라미터 검증 (Path Traversal 방어)
{: .no_toc}

`image.jsp`처럼 외부 입력값을 파일 경로 생성에 사용할 때는 `../`와 같은 상위 디렉터리 이동 문자열을 제거하거나 필터링해야 합니다.<br> 또한, 파일의 이름만 입력받고 실제 저장 경로는 서버 측에서 안전하게 결합하는 화이트리스트 방식을 채택해야 합니다.

###  코드 스페이스를 이용한 구현
{: .no_toc}

<div style="text-align: center; margin: 20px 0;">
  <img src="{{ '/images/TomcatManager/check.png' | relative_url }}"
       alt="image.jsp suri"
       style="max-width: 80%; height: auto; border: 1px solid #ddd; border-radius: 5px;">
  <p style="font-size: 0.9em; color: #ffffff;">[image.jsp suri]</p>
</div>

위 사진은 image.jsp 로직에 파일을 읽기 전 검증하는 로직을 추가한 것입니다.


<div style="text-align: center; margin: 20px 0;">
  <img src="{{ '/images/TomcatManager/path2.png' | relative_url }}"
       alt="방어 성공!"
       style="max-width: 80%; height: auto; border: 1px solid #ddd; border-radius: 5px;">
  <p style="font-size: 0.9em; color: #ffffff;">[방어 성공!]</p>
</div>



### (2) 톰캣 매니저 앱 자격 증명 관리 및 접근 제어
{: .no_toc}

실제 운영 환경에서는 `tomcat-users.xml`에 명시된<font color='#4ADE80'> 기본 관리자 계정 정보(`tomcat`, `admin` 등)를 반드시 변경</font>해야 하며, 사용하지 않는 매니저 앱 기능은 제거하는 것이 안전합니다. <br>
만약 사용해야 한다면 특정 내부 IP에서만 관리자 페이지에 접근할 수 있도록 아파치 혹은 톰캣 레벨에서<font color='#4ADE80'> ACL(접근 제어 리스트) 설정을 적용</font>해야 합니다.

---

## 5. 마치며

이번 문제는 소스코드 단의 **Path Traversal** 취약점이 어떻게 인프라 설정 파일 탈취로 이어지고, 나아가 관리자 페이지 기능 악용을 통한 **RCE(원격 코드 실행)**까지 체인 형태로 연결될 수 있는지 보여주며 전체적인 정보 탈취의 흐름을 보여준 유익한 문제였습니다. <br>

특히 코드가 막혔을 때 에러 메시지와 브라우저의 렌더링 방식(JPEG 필터링)을 이해하고, 개발자 도구의 네트워크 탭을 활용해 우회로(Ctrl + U)를 찾아냈던 과정이 가장 흥미로웠습니다.<br> 웹 해킹을 공부할 때는 단순히 소스코드만 볼 것이 아니라, 브라우저와 서버가 데이터를 주고받는 메커니즘을 명확히 이해하는 것이 역시 중요한 것 같습니다.
저는 아직 많이 부족해서.. 더 열심히 공부하도록 하겠습니다.

## 피드백은 언제나 환영입니다!
{: .no_toc}
부족한 글이지만 끝까지 읽어주셔서 감사합니다. 포스팅 내용 중 잘못된 정보가 있거나, 더 효율적인 분석 방법이 있다면 언제든지 댓글을 활용해 피드백 부탁드립니다!