# Test Cases – Gmail Maliciousness Checker

## Objective
To test whether the program identifies common phishing indicators in sample email messages.

| Test ID | Test Scenario | Sample Input | Expected Result |
|---|---|---|---|
| TC01 | Normal email | Subject: Meeting Reminder. Body: The project meeting is scheduled for tomorrow at 10 AM. | Low risk |
| TC02 | Urgent language | Subject: Urgent Action Required. Body: Your account will be suspended immediately. Verify your account now. | Risk should increase |
| TC03 | Insecure HTTP link | Subject: Account Notice. Body: Please visit http://example.com to view the notice. | Risk should increase |
| TC04 | Suspicious URL with embedded credentials | Subject: Security Alert. Body: Please visit http://example.com@evil.test/login | Risk should increase |
| TC05 | Email containing a shortened URL | Subject: Important Update. Body: Open https://bit.ly/example to view the details. | Risk should increase if shorteners are detected |

## Testing Procedure

1. Run the program using `python email_analyzer.py`.
2. Enter the sender address, subject, and body for each test.
3. Record the risk score and risk classification displayed by the program.
4. Compare the actual output with the expected result.
5. Investigate any unexpected results and update the program if necessary.

## Test Results

Actual scores and classifications will be recorded after executing the tests locally.

## Limitations

These tests use fictional sample data. The tool uses heuristic indicators and cannot guarantee that an email is malicious or safe.

