#!/usr/bin/env python3

import sys
import os
import json
import tempfile

# Add the src directory to the Python path
sys.path.insert(0, '/Users/douglascoburn/socket.dev/github/security-tools/src')

def test_socket_sca_failure():
    """Test that Socket SCA scan failures are properly detected"""
    
    # Create a temporary directory for test files
    with tempfile.TemporaryDirectory() as temp_dir:
        # Create the socket_sca_output.json file with failure data
        with open('/Users/douglascoburn/socket.dev/github/security-tools/test_socket_sca_failure.json', 'r') as f:
            failure_data = json.load(f)
        
        socket_sca_file = os.path.join(temp_dir, 'socket_sca_output.json')
        with open(socket_sca_file, 'w') as f:
            json.dump(failure_data, f)
        
        # Set the required environment variables
        original_temp_dir = os.environ.get('TEMP_OUTPUT_DIR')
        original_scm_disabled = os.environ.get('SOCKET_SCM_DISABLED')
        
        os.environ['TEMP_OUTPUT_DIR'] = temp_dir
        os.environ['SOCKET_SCM_DISABLED'] = 'true'
        
        try:
            # Import and test the load_json function first
            from socket_external_tools_runner import load_json, TOOL_CLASSES
            
            print(f"Testing load_json with file: {socket_sca_file}")
            socket_sca_data = load_json("socket_sca_output.json", "SocketSCA")
            print(f"Loaded data: {socket_sca_data}")
            
            if socket_sca_data:
                print(f"scan_failed: {socket_sca_data.get('scan_failed', False)}")
                print(f"new_alerts: {len(socket_sca_data.get('new_alerts', []))}")
            
            # Check if socket_sca is in TOOL_CLASSES
            print(f"TOOL_CLASSES: {list(TOOL_CLASSES.keys())}")
            
            # Test the SocketSCA processor
            if "socket_sca" in TOOL_CLASSES:
                from core.connectors.socket_sca import SocketSCA
                processor = SocketSCA()
                events = processor.process_output(socket_sca_data, temp_dir, "SocketSCA")
                print(f"Generated events: {len(events.get('events', []))}")
                for event in events.get('events', []):
                    print(f"Event: {event.__dict__}")
            else:
                print("socket_sca not in TOOL_CLASSES - checking environment variables")
                for var in ["INPUT_NODEJS_SCA_ENABLED", "INPUT_PYTHON_SCA_ENABLED"]:
                    print(f"{var}: {os.getenv(var, 'not set')}")
            
        except Exception as e:
            print(f"Exception during testing: {e}")
            import traceback
            traceback.print_exc()
            return False
        finally:
            # Restore original environment
            if original_temp_dir:
                os.environ['TEMP_OUTPUT_DIR'] = original_temp_dir
            elif 'TEMP_OUTPUT_DIR' in os.environ:
                del os.environ['TEMP_OUTPUT_DIR']
                
            if original_scm_disabled:
                os.environ['SOCKET_SCM_DISABLED'] = original_scm_disabled
            elif 'SOCKET_SCM_DISABLED' in os.environ:
                del os.environ['SOCKET_SCM_DISABLED']
    
    return True

if __name__ == '__main__':
    test_socket_sca_failure()
