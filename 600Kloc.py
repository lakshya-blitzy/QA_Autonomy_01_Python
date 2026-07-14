with open("large.csv", "w") as f:
    for i in range(600000):
        f.write(f"{i},Sample Data {i}\n")