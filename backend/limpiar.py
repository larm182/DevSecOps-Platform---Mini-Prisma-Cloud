import sqlite3

# Ruta a tu base de datos
DB_PATH = "devsecops.db"

def wipe_all_tables():
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        # Verifica qué tablas hay
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()

        # Elimina los datos de cada tabla (excepto sqlite_sequence si la hubiera)
        for (table_name,) in tables:
            if table_name != "sqlite_sequence":
                cursor.execute(f"DELETE FROM {table_name}")
                print(f"[✔] Datos eliminados de la tabla: {table_name}")

        conn.commit()
        print("[✔] Todas las tablas fueron limpiadas con éxito.")
    except Exception as e:
        print("[✘] Error:", e)
    finally:
        conn.close()

if __name__ == "__main__":
    confirm = input("¿Seguro que quieres eliminar TODOS los datos? (sí/no): ")
    if confirm.lower() in ["sí", "si", "yes", "y"]:
        wipe_all_tables()
    else:
        print("Operación cancelada.")


