import os
import pickle

class MYFileManager:

    def __init__(self):
        if not os.path.exists('data'): os.makedirs('data')
        self.filename = 'data/NoUpdates.kz'
        self.list_data = []  # Initialize as an empty list


    def write(self, data):
        self.append(data)


    def append(self, data):
        try:

            if os.path.exists(self.filename):
                # If the file exists, read the current data into list_data
                current_data = self.read()
                if current_data is not None:
                    self.list_data = current_data

            self.list_data.append(data)
     
            # Save the list_data to the file
            with open(self.filename, 'wb') as file:
                pickle.dump(self.list_data, file)

        except Exception as e:
            print(f"Failed to write data to {self.filename}: {e}")


    def read(self) -> list:
        if not os.path.exists(self.filename):
            print(f"{self.filename} does not exist.")
            return []
        try:
            with open(self.filename, 'rb') as file:
                self.list_data = pickle.load(file)
            # print(f"Data read from {self.filename}")
            return self.list_data
        except Exception as e:
            print(f"Failed to read data from {self.filename}: {e}")
            return []


    def save(self,):
        # Save the list_data to the file
        with open(self.filename, 'wb') as file:
            pickle.dump(self.list_data, file)
      
    def remove(self, value):
        try:
                
            self.list_data.remove(value)
            self.save()
        except Exception as e:
            print(e)


    def remove_file(self, ):
        if os.path.exists(self.filename):
            try:
                os.remove(self.filename)
                # print(f"{self.filename} has been removed.")
            except Exception as e:
                print(f"Failed to remove {self.filename}: {e}")
        else:
            print(f"{self.filename} does not exist.")


       


    def rename(self, new_name):
        if os.path.exists(self.filename):
            try:
                os.rename(self.filename, new_name)
                self.filename = new_name
                # print(f"File renamed to {new_name}")
            except Exception as e:
                print(f"Failed to rename {self.filename} to {new_name}: {e}")
        else:
            print(f"{self.filename} does not exist.")
