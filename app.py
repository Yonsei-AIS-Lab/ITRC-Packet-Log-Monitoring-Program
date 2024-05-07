from flask import Flask, render_template, Response, json
import os
import subprocess
import threading
import queue
import time
import psutil
from scapy.all import sniff

log_buffer = queue.Queue()
network_buffer = queue.Queue()
write_buffer = queue.Queue()  # write buffer 추가
db = queue.Queue()  # DB 시뮬레이션

app = Flask(__name__, template_folder=os.getcwd()+'/templates/')

@app.route('/')
def index():
    return render_template('index.html')

'''
Network Log Data Collection Code
'''
def fetch_windows_events():
    """PowerShell을 사용하여 윈도우 이벤트 로그 조회"""
    while True:
        start_time = time.time()
        command = 'Get-WinEvent -LogName System -MaxEvents 10 | Format-List'
        process = subprocess.Popen(["powershell", "-ExecutionPolicy", "Bypass", "-Command", command], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        result, error = process.communicate()

        if error:
            print(f"Error: {error.decode('cp949')}")
        else:
            output = result.decode('cp949')
            events = output.split('\r\n\r\n')
            for event in events:
                if event.strip():
                    log_buffer.put(event)
                    # log data to web
        
        time.sleep(5)  # 폴링 간격

'''
Network Packet Data Collection Code
'''
def packet_handler(packet):
    network_buffer.put(packet.summary())

'''
send_logs 및 send_packets으로 buffer_to_write_buffer 대체
'''
def send_logs(repeat_count=1):
    while True:
        event = None
        try:
            event = log_buffer.get(timeout=1)
            write_buffer.put(event[0])
            if repeat_count == 3:
                log_buffer.put(event)
        except queue.Empty:
            continue
        
        for _ in range(repeat_count):
            yield f"data: {json.dumps({'event': event})}\n\n"
        time.sleep(1)
        
@app.route('/previous_logs')
def send_log_previous():
    return Response(send_logs(3), mimetype='text/event-stream')

@app.route('/zerocopy_logs')
def send_log_zerocopy():
    return Response(send_logs(1), mimetype='text/event-stream')

def send_packets(repeat_count=1):
    while True:
        event = None
        try:
            event = network_buffer.get(timeout=1)
            write_buffer.put(event[0])
            if repeat_count == 3:
                network_buffer.put(event)
        except queue.Empty:
            continue
        
        for _ in range(repeat_count):
            yield f"data: {json.dumps({'event': event})}\n\n"
        time.sleep(1)
        
@app.route('/previous_packets')
def send_packet_previous():
    return Response(send_packets(3), mimetype='text/event-stream')

@app.route('/zerocopy_packets')
def send_packet_zerocopy():
    return Response(send_packets(1), mimetype='text/event-stream')

def db_writer():
    """Write buffer에서 DB로 데이터 이동 및 저장"""
    while True:
        if not write_buffer.empty():
            data = write_buffer.get()
            db.put(data)  # DB에 저장
            # processing_time = end_time - start_time  # 처리 시간 계산
            # print(f"DB 저장: {data}, 데이터당 처리 시간: {processing_time:.9f}초")
        
        time.sleep(0.5)  # DB에 쓰기 전 간단한 딜레이
     
'''
자원 사용량 모니터링
'''
@app.route('/system/metrics')
@app.route('/system/status')
def system_metrics():
    def generate():
        while True:
            cpu = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory().percent
            yield f"data: {json.dumps({'CPU Usage': cpu, 'Memory Usage' : memory})}\n\n"
            time.sleep(1)
    return Response(generate(), mimetype='text/event-stream')

if __name__ == '__main__':
    threading.Thread(target=fetch_windows_events, daemon=True).start()
    threading.Thread(target=lambda: sniff(prn=packet_handler, store=False), daemon=True).start()
    threading.Thread(target=db_writer, daemon=True).start()
    app.run(debug=True, threaded=True)
