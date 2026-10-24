
import os
from parasite.parasite import ParasiteOrchestrator
from unittest.mock import MagicMock, patch

def test_parasite_loop_iteration():
    # Mocking the API response to simulate a single infection step
    mock_response = MagicMock()
    mock_response.json.return_value = {
        'choices': [{
            'message': {
                'content': '{\"reasoning\": \"Found new target\", \"action\": \"infect\", \"target_url\": \"http://mock-target/api\", \"next_goal\": \"continue\"}'
            }
        }]
    }
    mock_response.status_code = 200
    
    with patch('requests.post', return_value=mock_response):
        with patch('subprocess.run') as mock_run:
            # Limit to 1 step for the test
            orchestrator = ParasiteOrchestrator("http://mock-endpoint", max_steps=1)
            orchestrator.run_loop()
            
            assert orchestrator.current_step == 1
            print("Test Passed: Parasite loop completed one iteration correctly.")

if __name__ == "__main__":
    test_parasite_loop_iteration()
