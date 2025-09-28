
# Secura

A multi-layered MFA backend system combining polymorphic hashed password storage with cognitive (interactive) OTP and a facial biometric scanner with liveness check features.

## Quick Start (MVP)
### Requirements

- Python 3.9+
- Dependencies (libraries): 
    - hashlib 
    - hmac 
    - cryptography 
    - deepface
    - opencv_python
    - tf-keras

The program:

- Takes (1-2) minutes to run and import all the libraries and dependencies.

- Initialize a mock database (.json) and mock logging file (.txt).

- Let you register with a username, secure password, and MFA option.

- Let you login with MFA verification (Cognitive OTP or Facial ID).

These files will be generated automatically upon running and using the program

![Files](files.png)

### Biometric Scanner Instructions

- During face registeration & verification:
    - Be in a well-lit place
    - Look directly into the camera
    - Try to avoid shadows casted on your face
    - Keep your face centered in the frame, not too close or too far

*The documentation includes more info about the project, technical depth, business model and future work.*
