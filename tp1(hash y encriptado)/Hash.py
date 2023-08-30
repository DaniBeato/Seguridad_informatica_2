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

if __name__ == "__main__":
    while True:
        print("\n----------------------------------------------------------------------------")
        print("1. Calcular hash de un archivo")
        print("2. Verificar si un archivo ha sido modificado")
        print("3. Salir")
        choice = input("Seleccione una opción: ")

        if choice == "1":
            file_path = input("Ingrese la ruta del archivo: ")
            hash_algorithm = input("Ingrese el algoritmo de hash (por defecto: sha256): ")
            if not hash_algorithm:
                hash_algorithm = "sha256"

            calculated_hash = calculate_hash(file_path, hash_algorithm)
            print(f"Hash calculado ({hash_algorithm}): {calculated_hash}")

        elif choice == "2":
            file_path = input("Ingrese la ruta del archivo: ")
            expected_hash = input("Ingrese el hash esperado: ")
            hash_algorithm = input("Ingrese el algoritmo de hash (por defecto: sha256): ")
            if not hash_algorithm:
                hash_algorithm = "sha256"

            is_verified = verify_hash(file_path, expected_hash, hash_algorithm)

            if is_verified:
                print("El archivo no ha sido modificado. El hash coincide.")
            else:
                print("El archivo ha sido modificado. El hash no coincide.")

        elif choice == "3":
            print("¡Hasta luego!")
            break

        else:
            print("Opción no válida. Por favor, elija una opción válida.")

