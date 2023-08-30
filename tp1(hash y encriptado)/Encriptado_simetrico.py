from cryptography.fernet import Fernet

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
            print("Archivo encriptado. La clave de encriptación es: ", key)

        elif choice == "2":
            key = input("Ingrese la clave de encriptación: ")
            input_file = input("Ingrese la ruta del archivo encriptado: ")
            decrypted_file = input("Ingrese la ruta del archivo desencriptado de salida: ")

            decrypt_file(input_file, decrypted_file, key.encode())
            print("Archivo desencriptado.")

        elif choice == "3":
            print("¡Hasta luego!")
            break

        else:
            print("Opción no válida. Por favor, elija una opción válida.")