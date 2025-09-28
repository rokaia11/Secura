#import essential libraries
import os, logging, random, time, json
from datetime import datetime
# preventing TensorFlow's internal operations overwheming outputs by setting the TensorFlow logging verbosity level to 2
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'
logging.getLogger("tensorflow").setLevel(logging.ERROR) #to show errors only
# Output delayer for UX
def print_pause(text):
    print(text)
    time.sleep(1.5)         
for message in ["Loading Secura MFA system....", "Initializing files...","Setting up MFA, Please wait..."]:
   print_pause(message)
#libraries required for password cryptography & biometric scanner   
from deepface import DeepFace
from cryptography.fernet import Fernet
import cv2
import numpy as np
import hashlib
import hmac

#Biometric scanner data
#creating the encrypted database file 
biometric_db_file = "database.enc"
key_file = "biometric_scanner_db.key"
if os.path.exists(key_file):
  with open(key_file , 'rb') as k:
    key = k.read()
else:
  key = Fernet.generate_key()
  with open(key_file, 'wb') as k:
    k.write(key)
os.environ['BIOMETRIC_DB_KEY'] = key.decode('utf-8')

#Biometric scanner main functions
# this function decrypts the database to enable us to read its content
def load_db():
  if os.path.exists(biometric_db_file):
    cipher = get_cipher()
    with open(biometric_db_file , 'rb') as f:
      cipher_text = f.read()
    try:
      plain_text = cipher.decrypt(cipher_text)
      return json.loads(plain_text.decode('utf-8'))
    except Exception as e:
      print(f"Failed to decrypt db an error happened {e}")
      return {}
  else:
    return {}
# this function encrypts the database in utf-8 style 
def save_db(user_dict):
  cipher = get_cipher()
  plain_text = json.dumps(user_dict).encode('utf-8')
  cipher_text = cipher.encrypt(plain_text)
  with open(biometric_db_file , 'wb')as f:
    f.write(cipher_text)
# this function captures the photo of the user and returns it as a uint format numpy array
def take_photo():
  camera = cv2.VideoCapture(0)
  if not camera.isOpened():
    print("Can`t open the camera")
    return None
  # setting the camera resolution to 640*480  which is a common and well supported resolution
  camera.set(cv2.CAP_PROP_FRAME_WIDTH, 640) #640 pixels width
  camera.set(cv2.CAP_PROP_FRAME_HEIGHT, 480) #480 pixels height
  # setting the camera brightness to 50%
  camera.set(cv2.CAP_PROP_BRIGHTNESS, 0.5) 
  try :
    boolean , capture = camera.read()
    if boolean is True:
      if capture.dtype != np.uint8:
        capture = (capture * 255).astype("uint8")
      return capture
    else:
      print("couldn`t capture the image")
      return None
  finally:
    camera.release()

# this function generate the environment cipher
def get_cipher():
  key = os.environ.get('BIOMETRIC_DB_KEY')
  if not key:
    raise RuntimeError ('Missing Key : Please enter it before running')
  if isinstance(key, str):
    return Fernet(key.encode())
  else:
    if isinstance(key, bytes):
      return Fernet(key)
    else:
      raise RuntimeError('The key type is invalid must be a string or bytes')
    
# This function handles the cases if the user take a photo with no faces, blurred face, or multiple faces
def detecting_main_face(capture_array):
  print('detecting the main face...')
  try:
    detection = DeepFace.extract_faces(capture_array , detector_backend= 'ssd', enforce_detection= False , align= False)
    if len(detection) == 0:
      print('couldn`t detect any faces')
      return None
    if len(detection) == 1:
      return detection[0]['face'] 
    biggest_face = max(detection, key=lambda x: x['facial_area']['w'] * x['facial_area']['h'])
    face = biggest_face['face']
    if face.dtype != np.uint8:
      face = (face * 255).astype("uint8")
      return face
  except Exception as e:
    print(f"{e} an error happened while detection")
    return None

#This function checks if the person is a real person or justa static image or video
def liveness_check():
  print('Please, turn your head left and then right')
  capture1 = take_photo()
  time.sleep(0.7)
  capture2 = take_photo()
  detection1 = DeepFace.extract_faces(capture1 , detector_backend="ssd", enforce_detection=False, align = False)
  detection2 = DeepFace.extract_faces(capture2 , detector_backend="ssd", enforce_detection=False, align= False)
  if not detection1 or not detection2:
    print('couldn`t detect any faces')
    return False
  x1 = detection1[0]['facial_area']['x']
  x2 = detection2[0]['facial_area']['x']
  face_width1 = detection1[0]['facial_area']['w']
  face_width2 = detection2[0]['facial_area']['w']
  absolute_movement = abs(x1 - x2)
  average_width = (face_width1 + face_width2) / 2
  relative_movement = (absolute_movement / average_width) * 100
  if relative_movement > 10:
    return True
  else:
    print('Couldn`t detect a live person')
    return False


#this function is used the first time when the user registers
def facial_register(user_name):
  db = load_db()
  print('Starting the facial registering process...\n------------------------------')
  for message in ["Make sure you're in a well-lit place", "Look directly at the camera", "Ensure that there're no shadows over your face"]:
     print_pause(message)
  capture = take_photo()
  if capture.dtype != np.uint8:
    capture = (capture * 255).astype("uint8")
  try:
    main_face = detecting_main_face(capture)
    if main_face is None:
      print('Can`t register the user')
      return False
    if main_face.dtype != np.uint8:
      main_face = (main_face * 255).astype("uint8")
    face_embedding_vector = DeepFace.represent(img_path= main_face , model_name="ArcFace", enforce_detection=False)[0]['embedding']
    db[user_name] = face_embedding_vector
    save_db(db)
    return capture
  except Exception as e:
    print(f'{e} an error happened while registering the user')
    return None
    

#the main function for the scan and it turns only true or false
def facial_verification(user_name):
  db = load_db()
  standard_distance =0.45 #based on previous tests
  if user_name not in db:
    print('User not found')
    return None
  if not liveness_check():
    print('couldn`t detect an alive person')
    return None
  print('Now return your head to its natural position')
  time.sleep(3)

  capture = take_photo()
  if capture is None:
    return None
  if capture.dtype != np.uint8:
        capture = (capture * 255).astype("uint8")

  main_face = detecting_main_face(capture)
  if main_face is None:
    return None
  if main_face.dtype != np.uint8:
    main_face = (main_face * 255).astype("uint8")
  try:
    live_embedding = DeepFace.represent(img_path= main_face , model_name="ArcFace" , enforce_detection = False , detector_backend = "ssd")[0]['embedding']
    stored_image_embedding = np.array(db[user_name])
    live_embedding = live_embedding / np.linalg.norm(live_embedding)
    stored_image_embedding = stored_image_embedding / np.linalg.norm(stored_image_embedding)
    if len(live_embedding) == 0 or len(stored_image_embedding) == 0:
      print("An empty embedding detected")
      return None
    cosine_similarity = np.dot(live_embedding , stored_image_embedding )
    cosine_distance = 1- cosine_similarity
    if cosine_distance <= standard_distance:
      return True
    else:
      return False
  except Exception as e:
    print(f'{e} An error heppened while verifying')
    return None

def secura_main():  
    # Creating database as JSON file 
    db_file = "Database.json"
    if os.path.exists(db_file):
        with open(db_file, "r") as json_file:
            db = json.load(json_file)
    else:
        db = {}

    # Creating Log file as .txt file
    def log_write(log):
        current_time = datetime.now()
        timestamp = current_time.strftime("%Y-%m-%d   %H:%M:%S")
        with open("Logs.txt", mode = "a") as log_file:
            log_file.write(f"{timestamp}      {log}\n")

    # Password sharding & polymorphic hashing function (using PBKDF2) "registeration phase"
    def password_sharding(password):
        half = len(password)//2
        shard1 = password[:half]
        shard2 = password[half:]
        salt1 = os.urandom(16)
        salt2 = os.urandom(16)
        # Polymorphic hashing through 2 different algorithms and iterations
        hash_shard1 = hashlib.pbkdf2_hmac("sha256", shard1.encode(), salt1, 600_000)
        hash_shard2 = hashlib.pbkdf2_hmac("sha512", shard2.encode(), salt2, 210_000)
        return hash_shard1.hex(), hash_shard2.hex(), salt1.hex(), salt2.hex()
    
    # Password verification function (stored hashed shards) "login phase comparision"
    def password_verify(password, stored_shards):
        stored_shard1, stored_shard2, hex_salt1, hex_salt2 = stored_shards
        half = len(password)//2
        shard1 = password[:half]
        shard2 = password[half:]
        salt1 = bytes.fromhex(hex_salt1)
        salt2 = bytes.fromhex(hex_salt2)
        shard1_digest = hashlib.pbkdf2_hmac("sha256", shard1.encode(), salt1, 600_000).hex()
        shard2_digest = hashlib.pbkdf2_hmac("sha512", shard2.encode(), salt2, 210_000).hex()
        return(hmac.compare_digest(stored_shard1, shard1_digest) and hmac.compare_digest(stored_shard2, shard2_digest))
    
    # Menu input specifity validation
    def remove(text):
        return text.replace(" ","")
    def valid_input(string , valids):
        while True:
            valid_input = remove(input(string).lower())
            if valid_input in valids:
                return valid_input
            else:
                print_pause("Invalid input, please try again")
    
    # Password strength validator
    def password_validation(Password: str):
        if len(Password) < 8:
            print("Your password must be at least 8 characters")
            return False
        if not any(character.isupper() for character in Password):
            print("Your password must contain at least 1 uppercase letter")
            return False
        if not any(character.isdigit() for character in Password):
            print("Your password must contain at least 1 digit")
            return False
        special_characters = "!@#$%^&*()-_=+[]}{|;:',.<>?/`~"
        if not any(character in special_characters for character in Password):
            print("Your password must contain at least one special character like $ or !")
            return False
        return True
    
    # Registeration Phase
    def register():
        username = input("Enter your username: ").lower()
        if username in db:
            print("Username is already taken. Try another one")
            return register()
        while True:
            password = input("Enter a password: ")
            if password_validation(password) is True:
                break
        # PBKDF2 sharding process
        shard1, shard2, salt1, salt2 = password_sharding(password)
        # Storing data to json db
        db[username] = [shard1, shard2, salt1, salt2]
        with open(db_file, "w") as json_file:
            json.dump(db, json_file)
        log_write(f"[INFO] New user '{username}' is registered.")
        facial_id = valid_input('Do you want to add your facial id for a faster and more secure access? (y/n) ', ['yes','no', 'y', 'n'])
        if facial_id == "yes" or facial_id == "y":
           facial_register(username)
        log_write(f"[SUCCESS] New user '{username}' Facial ID registered successfully.")
        print_pause("Successful Registeration! Redirected to main portal....")
        return username        

    def cognitive_opt(username):
      # 6-digit OTP
      otp = str(random.randint(100000, 999999))
      print(f"OTP is {otp}")
      order1 = random.randint(1,6)
      order2 = random.randint(1,6)
      order3 = random.randint(1,6) 
      start_time = time.time()
      attempts = 0
      max_attempts = 3
      log_attempt = 0 
      while attempts < max_attempts:
        input1 = input(f"Enter the {order1}th number of your OTP: ")
        input2 = input(f"Enter the {order2}th number of your OTP: ")
        input3 = input(f"Enter the {order3}th number of your OTP: ")
        if not (input1.isdigit() and input2.isdigit() and input3.isdigit()):
            print("Invalid input, Please enter numbers only")
            continue   
        elapsed_time = time.time() - start_time
        if elapsed_time < 30 and int(input1) == int(otp[order1-1]) and int(input2) == int(otp[order2-1]) and int(input3) == int(otp[order3-1]):
            log_write(f"[SUCCESS] Correct OTP entered by user '{username}'.")
            print_pause("Logged in successfully!")
            return True                                      # End login
        elif elapsed_time > 30:                              # Expiry timed case
            log_write(f"[FAIL] OTP expired for user '{username}'.")
            print_pause("Access Denied. Expired OTP.")
            break
        else:                                                # Incorrect OTP case
            log_write(f"[FAIL] Incorrect OTP entered by user '{username}'.")
            attempts += 1
            print_pause("Access Denied. Incorrect OTP.")
            log_write(f"[WARNING] OTP attempt {attempts} for user '{username}'.")
            # OTP attempts exceeded case
            if attempts == max_attempts:
                log_write(f"[WARNING] User '{username}' exceeded OTP attempts.")
                print_pause("[ERROR] Exceeded number of OTP attempts.")
                log_attempt += 1
                print_pause("-----------------------------------------------------")
                print_pause("Redirecting to login screen...")
    # Logging in process
    def login():
        log_attempt = 0 
        max_log_attempts = 3
        while log_attempt < max_log_attempts:
            username = input("Enter the username: ").lower()
            password = input("Enter the password: ")
            if username in db and password_verify(password,db[username]):
                log_write(f"[SUCCESS] User '{username}' entered correct credentials.")
                print_pause("Credentials are successfully found! Proceeding to MFA...")
                print_pause("-----------------------------------------------------")
                facial_db = load_db()
                if username not in facial_db:
                   return cognitive_opt(username)
                else:
                   MFA = valid_input("How would you like to verify your identity? Face ID(1) or OTP(2)", ['1', '2'])
                   if MFA == "1":
                    # scanning when the user log in to see if the face mathces
                      result = facial_verification(username)
                      if result == True:
                        log_write(f"[SUCCESS] Facial ID verified for user '{username}'")
                        print('user matches, welcome to your account')
                        return True
                      elif result == False:
                        log_write(f"[WARNING] Facial ID verification failed for user '{username}'")
                        print('user didn`t match ')
                        return False
                      else:
                        log_write(f"[ERROR] Facial ID could not be detected for user '{username}'")
                        print('Can`t detect your face ')
                        return False
                   else:
                      return cognitive_opt(username)
    
            else:
                print_pause("Invalid credentials, Access Denied.")
                log_attempt += 1
                log_write(f"[WARNING] Login attempt {log_attempt} with invalid credentials for '{username}'.")
        # Temporary system lockout 
        log_write("[ERROR] Maximum login attempts reached. Access blocked.")
        print_pause("[ERROR] Maximum login attempts reached. \nLOCKING...")
        locktime = 5
        while locktime >= 0:
            print(f"\rTrying again in {locktime}....", end="", flush=True)
            time.sleep(2)
            locktime -= 1
    # Main portal (Navigation)
    def portal():
        while True:
            print_pause("\n----------------------------------------------")
            print_pause('Welcome! \nEnter the number of the operation you want: ')
            print_pause('1- Register a new account')
            print_pause('2- Already have an account? Login to your account')
            print_pause('3- Exit the program')
            option = valid_input('Register(1) , Login(2) , Exit(3) ', ['1','2', '3'])
            if option == '1' :
                print("Registeration.....")
                print_pause("--------------------------------")
                register()
            elif option == '2':
                print_pause("Proceeding to login portal.....")
                if login():
                    break
            else:
                exit()    
    portal()
secura_main()