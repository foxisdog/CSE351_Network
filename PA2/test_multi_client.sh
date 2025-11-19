#!/bin/bash

PORT=5678
HOST="localhost"
CLIENT_COUNT=50 # 동시에 접속할 클라이언트 수

echo "=========================================================="
echo "멀티 클라이언트 테스트 시작 (클라이언트 50개, nc 사용)"
echo "주의: 이 스크립트를 실행하기 전에 './proxy 5678' 서버가 실행 중이어야 합니다."
echo "=========================================================="

# HTTP 요청 생성
REQUEST="GET http://www.example.com/ HTTP/1.0\r\nHost: www.example.com\r\n\r\n"

# 50개 클라이언트를 동시에 실행하여 요청 전송
echo "${CLIENT_COUNT}개의 클라이언트가 동시에 요청을 보냅니다..."
for i in $(seq 1 $CLIENT_COUNT); do
  # nc을 사용하여 요청을 보내고 응답을 파일에 저장 (백그라운드 실행)
  ( (
    echo -e "$REQUEST"
    sleep 1
  ) | nc $HOST $PORT) >"client_output_${i}.txt" &
done

# 모든 백그라운드 작업(클라이언트)이 끝날 때까지 대기
wait
echo "모든 클라이언트가 응답을 받았습니다."

# 결과 확인
SUCCESS_COUNT=0
for i in $(seq 1 $CLIENT_COUNT); do
  if grep -q "HTTP/1.0 200 OK" "client_output_${i}.txt"; then
    SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
  else
    echo "클라이언트 ${i}: 오류가 발생했거나 유효한 응답을 받지 못했습니다."
  fi
  rm "client_output_${i}.txt" # 확인 후 임시 파일 삭제
done

echo "성공적으로 응답받은 클라이언트 수: ${SUCCESS_COUNT} / ${CLIENT_COUNT}"

# 최종 결과 출력
if [ $SUCCESS_COUNT -eq $CLIENT_COUNT ]; then
  echo -e "\n[성공] 모든 클라이언트가 정상적으로 응답을 받아 멀티 클라이언트 지원이 확인되었습니다. ✅"
else
  echo -e "\n[실패] 일부 클라이언트가 정상적인 응답을 받지 못했습니다."
fi

