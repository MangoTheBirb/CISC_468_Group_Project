import os

SHARED_FILES_DIR = "shared_files"

def initialize_shared_files():
    if not os.path.exists(SHARED_FILES_DIR):
        os.makedirs(SHARED_FILES_DIR)

def get_shared_files():
    try:
        files = os.listdir(SHARED_FILES_DIR)
        return files
    except Exception as e:
        print(f"Error getting shared files: {e}")
        return []
    
def add_shared_file(filepath):
    if not os.path.exists(filepath):
        print(f"File: {filepath} does not exist.")
        return
    filename = os.path.basename(filepath)
    try:
        shared_filepath = os.path.join(SHARED_FILES_DIR, filename)
        with open(filepath, "rb") as f:
            with open(shared_filepath, "wb") as f_shared:
                f_shared.write(f.read())
        print(f"Added file: {filename}")
    except Exception as e:
        print(f"Error adding file: {filename}: {e}")
    pass

def remove_shared_file(filename):
    try:
        filepath = os.path.join(SHARED_FILES_DIR, filename)
        if not os.path.exists(filepath):
            print(f"File: {filename} does not exist and is not shared.")
            return
        os.remove(filepath)
        print(f"Removed file: {filename}")
    except Exception as e:
        print(f"Error deleting file: {filename}: {e}")