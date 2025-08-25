#!/usr/bin/env python3

import sys
import os
import json
import tempfile
import shutil

# Add the src directory to the Python path
sys.path.insert(0, '/Users/douglascoburn/socket.dev/github/security-tools/src')

def test_real_socket_sca_failure():
    """Test with the actual Socket SCA failure output provided by the user"""
    
    # Create a temporary directory for test files
    with tempfile.TemporaryDirectory() as temp_dir:
        # Copy the real Socket SCA failure JSON to the temp directory
        with open('/Users/douglascoburn/socket.dev/github/security-tools/real_socket_sca_failure.json', 'r') as f:
            failure_data = json.load(f)
        
        socket_sca_file = os.path.join(temp_dir, 'socket_sca_output.json')
        with open(socket_sca_file, 'w') as f:
            json.dump(failure_data, f)
        
        print(f"Created test file: {socket_sca_file}")
        print(f"File contents: {json.dumps(failure_data, indent=2)[:200]}...")
        
        # Set the required environment variables
        original_env = {}
        test_env = {
            'TEMP_OUTPUT_DIR': temp_dir,
            'SOCKET_SCM_DISABLED': 'true',
            'INPUT_SOCKET_SCA_ENABLED': 'true'  # Enable Socket SCA processing
        }
        
        for key, value in test_env.items():
            original_env[key] = os.environ.get(key)
            os.environ[key] = value
        
        try:
            # Import and test step by step
            from socket_external_tools_runner import main, TOOL_CLASSES
            
            print(f"TOOL_CLASSES keys: {list(TOOL_CLASSES.keys())}")
            
            if "socket_sca" not in TOOL_CLASSES:
                print("ERROR: socket_sca not in TOOL_CLASSES")
                print("Available environment variables:")
                for key in ['INPUT_NODEJS_SCA_ENABLED', 'INPUT_PYTHON_SCA_ENABLED', 'INPUT_SOCKET_SCA_ENABLED']:
                    print(f"  {key}: {os.environ.get(key, 'not set')}")
                return False
            
            # This should exit with code 1 due to scan failure and critical alerts
            print("Testing Socket SCA failure handling with real data...")
            try:
                main()
                print("ERROR: main() should have exited with code 1!")
                return False
            except SystemExit as e:
                if e.code == 1:
                    print("SUCCESS: main() correctly exited with code 1 for scan failure")
                    return True
                else:
                    print(f"ERROR: main() exited with code {e.code}, expected 1")
                    return False
            
        except Exception as e:
            print(f"Exception during testing: {e}")
            import traceback
            traceback.print_exc()
            return False
        finally:
            # Restore original environment
            for key, original_value in original_env.items():
                if original_value is not None:
                    os.environ[key] = original_value
                elif key in os.environ:
                    del os.environ[key]
    
    return True

if __name__ == '__main__':
    success = test_real_socket_sca_failure()
    sys.exit(0 if success else 1)
