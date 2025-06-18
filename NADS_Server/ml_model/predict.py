import joblib
import os
from functools import lru_cache
import pandas as pd
import numpy as np
import socket
from dashboard.models import AttackLog
from datetime import datetime

hostname = socket.gethostname()
local_ip = socket.gethostbyname(hostname)

@lru_cache
def load_model():
    model_path = os.path.join(os.path.dirname(__file__), 'NADS_model.pkl')
    return joblib.load(model_path)

def predict_intrusion(data):
    model = load_model()
    try:
        if data['Src IP'] != local_ip:
            print(data['Src IP'])
            print(local_ip)
            df = pd.DataFrame([data])
            df = df.drop(columns=['Flow ID', 'Src IP', 'Dst IP', 'Timestamp','TotLen Bwd Pkts', 'Fwd Pkt Len Std', 'Bwd Pkt Len Std', 'Flow IAT Min', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd Header Len', 'Bwd Pkts/s', 'Pkt Len Min', 'Pkt Len Max', 'Pkt Len Mean', 'Pkt Len Std', 'PSH Flag Cnt', 'Pkt Size Avg', 'Fwd Seg Size Avg', 'Bwd Seg Size Avg', 'Subflow Fwd Pkts', 'Subflow Fwd Byts', 'Subflow Bwd Pkts', 'Subflow Bwd Byts', 'Fwd Act Data Pkts', 'Active Max', 'Idle Mean', 'Idle Max', 'Idle Min', 'Label'])
            df.replace([np.inf, -np.inf], np.nan, inplace=True)

            try:
                final = model.predict(df)
                print(final[0])
                AttackLog.objects.create(
                    host_ip = data['Src IP'],
                    destination_ip = data['Dst IP'],
                    attack = final[0],
                    timestamp = datetime.strptime(data['Timestamp'], "%d/%m/%Y %I:%M:%S %p")
                )
            except ValueError as e:
                print("ValueError", e)
    except Exception as e:
        print("Exception", e)