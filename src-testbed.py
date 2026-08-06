#!/usr/bin/env python3
"""
Testbed environment for Logistics 4.0 authentication protocol
"""

import time
import numpy as np
from datetime import datetime
from .entities import CloudServer, OperatorDevice, ETag
from .metrics import metrics


class Logistics40Testbed:
    """Complete testbed for Logistics 4.0 authentication protocol"""
    
    def __init__(self, num_sessions: int = 100):
        self.cloud_server = CloudServer("CS_MAIN")
        self.operator = OperatorDevice("OP_001", "", "")
        self.e_tag = ETag("ET_001", "", "")
        self.num_sessions = num_sessions
        self.results = []
    
    def run_registration_phase(self) -> bool:
        """Execute registration phase"""
        print("\n" + "="*60)
        print("PHASE 1: REGISTRATION")
        print("="*60)
        
        tag_success = self.e_tag.register(self.cloud_server)
        operator_success = self.operator.register(self.cloud_server)
        
        return tag_success and operator_success
    
    def run_single_authentication(self) -> dict:
        """Execute a single authentication session"""
        session_start = time.perf_counter()
        
        timestamp = time.time()
        success, op_response = self.operator.initiate_authentication(
            self.cloud_server, timestamp
        )
        
        if not success:
            return {'success': False, 'reason': 'Operator authentication failed'}
        
        success, et_response = self.e_tag.authenticate(op_response, timestamp)
        
        if not success:
            return {'success': False, 'reason': 'E-Tag authentication failed'}
        
        success, final_response = self.cloud_server.finalize_authentication(
            et_response, self.operator.id_o
        )
        
        session_end = time.perf_counter()
        session_time_ms = (session_end - session_start) * 1000
        
        metrics.record_session(session_time_ms, 2688)
        
        return {
            'success': success,
            'session_time_ms': session_time_ms,
            'sk_generated': self.operator.current_sk is not None
        }
    
    def run_authentication_batch(self) -> list:
        """Run multiple authentication sessions"""
        print("\n" + "="*60)
        print(f"PHASE 2: AUTHENTICATION ({self.num_sessions} sessions)")
        print("="*60)
        
        results = []
        for i in range(self.num_sessions):
            if (i + 1) % 20 == 0:
                print(f"  Progress: {i+1}/{self.num_sessions} sessions")
            results.append(self.run_single_authentication())
            time.sleep(0.001)
        
        return results
    
    def run_key_update_phase(self) -> bool:
        """Execute key update phase"""
        print("\n" + "="*60)
        print("PHASE 3: KEY UPDATE AND RE-AUTHENTICATION")
        print("="*60)
        
        update_request = self.cloud_server.init_key_update()
        
        op_success, _ = self.operator.update_key(
            update_request, update_request['timestamp']
        )
        et_success, _ = self.e_tag.update_key(
            update_request, update_request['timestamp']
        )
        
        return op_success and et_success
    
    def run_full_testbed(self) -> dict:
        """Execute complete testbed evaluation"""
        print("\n" + "="*60)
        print("LOGISTICS 4.0 AUTHENTICATION PROTOCOL TESTBED")
        print("="*60)
        print(f"Start Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Total Sessions: {self.num_sessions}")
        
        registration_success = self.run_registration_phase()
        if not registration_success:
            return {'error': 'Registration failed'}
        
        auth_results = self.run_authentication_batch()
        key_update_success = self.run_key_update_phase()
        
        successful_sessions = sum(1 for r in auth_results if r['success'])
        avg_session_time = np.mean([r['session_time_ms'] for r in auth_results if r['success']])
        
        return {
            'registration_success': registration_success,
            'key_update_success': key_update_success,
            'total_sessions': self.num_sessions,
            'successful_sessions': successful_sessions,
            'success_rate': successful_sessions / self.num_sessions * 100,
            'avg_authentication_time_ms': avg_session_time,
            'communication_overhead_bits': 2688,
            'performance_metrics': metrics.report(),
            'completion_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }