import json

# Class to manage File I/O for the program
# This class should be utilized by the GUI
# to save or load analyzed data
# Uses JSON dumping and loading to easily serialize / deserialize analytics


class EntropyDataManager:
    def __init__(self, filename):
        self.filename = filename

    # Opens the file of what self.filename currently is
    # (returns what json.load obtains)
    def openFile(self):
        f = open(self.filename, "r")
        try:
            return json.load(f)
        except ValueError:
            return "Error: selected file is not in JSON format!"

    # Saves the given data to what self.filename currently is
    def saveFile(self, data):
        f = open(self.filename, "w")
        try:
            json.dump(data, f)
        except TypeError:
            print "Error: cannot dump given data (not JSON serializable)!"



