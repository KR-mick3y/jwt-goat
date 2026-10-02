# jwt-goat
JWT를 인증 수단으로 사용하는 환경에서 발생 가능한 취약점 유형들을 실습할 수 있는 Docker 기반 환경입니다.

## 실행
```
git clone https://github.com/KR-mick3y/jwt-goat.git
cd jwt-goat
docker compose up --build -d
```

## 종료
```
docker compose down
```

# Labs
| # | 취약점 | URL |
|---|-------|--------|
| 01 | JWT alg:none Attack | http://127.0.0.1:9001|
| 02 | kid Injection | http://127.0.0.1:9002|
| 03 | Algorithm Confusion | http://127.0.0.1:9003 |
| 04 | JWT Secret Brute Force | http://127.0.0.1:9004 |
| 05 | JKU SSRF | http://127.0.0.1:9005|

