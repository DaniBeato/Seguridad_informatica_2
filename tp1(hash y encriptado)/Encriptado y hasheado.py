from cryptography.fernet import Fernet
import hashlib

def calculate_hash(file_path, hash_algorithm="sha256"):
    hash_obj = hashlib.new(hash_algorithm)
    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            hash_obj.update(chunk)
    return hash_obj.hexdigest()

def verify_hash(file_path, expected_hash, hash_algorithm="sha256"):
    calculated_hash = calculate_hash(file_path, hash_algorithm)
    return calculated_hash == expected_hash


def generate_key():
    return Fernet.generate_key()

def encrypt_file(input_file, output_file, key):
    with open(input_file, 'rb') as f:
        plaintext = f.read()

    fernet = Fernet(key)
    ciphertext = fernet.encrypt(plaintext)

    with open(output_file, 'wb') as f:
        f.write(ciphertext)

def decrypt_file(input_file, output_file, key):
    with open(input_file, 'rb') as f:
        ciphertext = f.read()

    fernet = Fernet(key)
    decrypted_data = fernet.decrypt(ciphertext)

    with open(output_file, 'wb') as f:
        f.write(decrypted_data)

if __name__ == "__main__":
    while True:
        print("\n----------------------------------------------------------------------------")
        print("1. Encriptar archivo")
        print("2. Desencriptar archivo")
        print("3. Salir")
        choice = input("Seleccione una opción: ")

        if choice == "1":
            key = generate_key()
            input_file = input("Ingrese la ruta del archivo a encriptar: ")
            encrypted_file = input("Ingrese la ruta del archivo encriptado de salida: ")
            encrypt_file(input_file, encrypted_file, key)

            hash_algorithm = input("Ingrese el algoritmo de hash (por defecto: sha256): ")
            if not hash_algorithm:
                hash_algorithm = "sha256"
            calculated_hash = calculate_hash(input_file, hash_algorithm)

            print(f"Hash calculado ({hash_algorithm}): {calculated_hash}")
            print("Archivo encriptado. La clave de encriptación es: ", key)

        elif choice == "2":
            key = input("Ingrese la clave de encriptación: ")
            input_file = input("Ingrese la ruta del archivo encriptado: ")
            decrypted_file = input("Ingrese la ruta del archivo desencriptado de salida: ")
            decrypt_file(input_file, decrypted_file, key.encode())

            hash_algorithm = input("Ingrese el algoritmo de hash (por defecto: sha256): ")
            if not hash_algorithm:
                hash_algorithm = "sha256"
            calculated_hash = calculate_hash(input_file, hash_algorithm)
            expected_hash = input("Ingrese el hash esperado: ")
            if not hash_algorithm:
                hash_algorithm = "sha256"

            is_verified = verify_hash(decrypted_file, expected_hash, hash_algorithm)

            if is_verified:
                print("Archivo desencriptado.")
                print("El archivo no ha sido modificado. El hash coincide.")
            else:
                print("Archivo desencriptado.")
                print("El archivo ha sido modificado. El hash no coincide.")

        elif choice == "3":
            print("¡Hasta luego!")
            break

        else:
            print("Opción no válida. Por favor, elija una opción válida.")