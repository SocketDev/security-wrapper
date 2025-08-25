#!/usr/bin/env python3

import sys
import os
import json
import tempfile
import shutil

# Add the src directory to the Python path
sys.path.insert(0, '/Users/douglascoburn/socket.dev/github/security-tools/src')

from socket_external_tools_runner import main

def test_socket_sca_failure():
    """Test that Socket SCA scan failures are properly detected and cause exit(1)"""
    
    # Create a temporary directory for test files
    with tempfile.TemporaryDirectory() as temp_dir:
        # Create the socket_sca_output.json file with failure data
        with open('/Users/douglascoburn/socket.dev/github/security-tools/test_socket_sca_failure.json', 'r') as f:
            failure_data = json.load(f)
        
        socket_sca_file = os.path.join(temp_dir, 'socket_sca_output.json')
        with open(socket_sca_file, 'w') as f:
            json.dump(failure_data, f)
        
        # Set the TEMP_OUTPUT_DIR environment variable
        original_temp_dir = os.environ.get('TEMP_OUTPUT_DIR')
        os.environ['TEMP_OUTPUT_DIR'] = temp_dir
        
        try:
            # This should exit with code 1 due to scan failure
            print("Testing Socket SCA failure handling...")
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
            print(f"ERROR: Unexpected exception: {e}")
            return False
        finally:
            # Restore original environment
            if original_temp_dir:
                os.environ['TEMP_OUTPUT_DIR'] = original_temp_dir
            elif 'TEMP_OUTPUT_DIR' in os.environ:
                del os.environ['TEMP_OUTPUT_DIR']

if __name__ == '__main__':
    success = test_socket_sca_failure()
    sys.exit(0 if success else 1)
