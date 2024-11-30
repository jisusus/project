import os
import sys
import argparse
import logging
from math import sqrt
from math import pi
from math import exp

def separate_by_class(instance, label):
	separated = dict()
	for i in range(len(instance)):
		vector = instance[i]
		class_value = label[i]
		if (class_value not in separated):
			separated[class_value] = []
		separated[class_value].append(vector)
	return separated

def is_float(value):
    try:
        float(value)
        return True
    except ValueError:
        return False

# Calculate the mean of a list of numbers
def mean(numbers):
    # 숫자로 변환 가능한 값만 계산
    numbers = [float(x) for x in numbers if is_float(x)]
    return sum(numbers) / float(len(numbers))

# Calculate the standard deviation of a list of numbers
def stdev(numbers):
    # 숫자로 변환 가능한 값만 계산
    numbers = [float(x) for x in numbers if is_float(x)]
    avg = mean(numbers)
    variance = sum([(x - avg) ** 2 for x in numbers]) / (len(numbers) - 1)
    return variance ** 0.5

# Summarize a dataset (skip first column)
def summarize_dataset(dataset):
    summaries = [
        (mean(column), stdev(column), len(column))
        for column in zip(*[a[1:] for a in dataset])
    ]
    return summaries

# Summarize by class
def summarize_by_class(instance, label):
    separated = {}
    for i in range(len(instance)):
        class_value = label[i]
        if class_value not in separated:
            separated[class_value] = []
        separated[class_value].append(instance[i])
    summaries = {}
    for class_value, rows in separated.items():
        summaries[class_value] = summarize_dataset(rows)
    return summaries

# Calculate the Gaussian probability distribution function for x
def calculate_probability(x, mean, stdev):
	exponent = exp(-((x-mean)**2 / (2 * stdev**2 )))
	return (1 / (sqrt(2 * pi) * stdev)) * exponent
 
# Calculate the probabilities of predicting each class for a given row
def calculate_class_probabilities(summaries, row, list):
	total_rows = sum([summaries[label][0][2] for label in summaries])
	probabilities = dict()
	for class_value, class_summaries in summaries.items():
		probabilities[class_value] = summaries[class_value][0][2]/float(total_rows)
		for i in list:
			mean, stdev, _ = class_summaries[i]
			probabilities[class_value] *= calculate_probability(row[i+1], mean, stdev)
	return probabilities

def training(instances, labels):
    summaries = summarize_by_class(instances, labels)
    return summaries

def predict(instance, parameters, list):
    probabilities = calculate_class_probabilities(parameters, instance, list)
    best_label, best_prob = None, -1
    for class_value, probability in probabilities.items():
        if best_label is None or probability > best_prob:
            best_prob = probability
            best_label = class_value
    return best_label

def report(predictions, answers):
    if len(predictions) != len(answers):
        logging.error("The lengths of two arguments should be same")
        sys.exit(1)

    # accuracy
    correct = 0
    for idx in range(len(predictions)):
        if predictions[idx] == answers[idx]:
            correct += 1
    accuracy = round(correct / len(answers), 2) * 100

    # precision
    tp = 0
    fp = 0
    for idx in range(len(predictions)):
        if predictions[idx] == 1:
            if answers[idx] == 1:
                tp += 1
            else:
                fp += 1
    precision = round(tp / (tp + fp), 2) * 100

    # recall
    tp = 0
    fn = 0
    for idx in range(len(answers)):
        if answers[idx] == 1:
            if predictions[idx] == 1:
                tp += 1
            else:
                fn += 1
    recall = round(tp / (tp + fn), 2) * 100

    logging.info("accuracy: {}%".format(accuracy))
    logging.info("precision: {}%".format(precision))
    logging.info("recall: {}%".format(recall))

def load_raw_data(fname):
    instances = []
    labels = []
    with open(fname, "r") as f:
        f.readline()
        for line in f:
            tmp = line.strip().split(", ")
            tmp[1] = float(tmp[1])
            tmp[2] = float(tmp[2])
            tmp[3] = float(tmp[3])
            tmp[4] = float(tmp[4])
            tmp[5] = int(tmp[5])
            tmp[6] = int(tmp[6])
            tmp[7] = float(tmp[7])
            tmp[8] = int(tmp[8])
            instances.append(tmp[:-1])
            labels.append(tmp[-1])
    return instances, labels

def run(train_file, test_file, parameter):
    # training phase
    instances, labels = load_raw_data(train_file)
    logging.debug("instances: {}".format(instances))
    logging.debug("labels: {}".format(labels))
    parameters = training(instances, labels)

    # testing phase
    instances, labels = load_raw_data(test_file)
    predictions = []
    for instance in instances:
        result = predict(instance, parameters, parameter)
        if result not in [0, 1]:
            logging.error("The result must be either 0 or 1")
            sys.exit(1)

        predictions.append(result)
    
    # report
    report(predictions, labels)

def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--training", required=True, metavar="<file path to the training dataset>", help="File path of the training dataset", default="training.csv")
    parser.add_argument("-u", "--testing", required=True, metavar="<file path to the testing dataset>", help="File path of the testing dataset", default="testing.csv")
    parser.add_argument("-l", "--log", help="Log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)", type=str, default="INFO")
    parser.add_argument("-p", "--parameter", help="(avg/max/min)*(temperature/humidity), power", type=str, default="0,1,2,3,4,5,6")
    
    args = parser.parse_args()
    return args

def main():
    args = command_line_args()
    logging.basicConfig(level=args.log)

    if not os.path.exists(args.training):
        logging.error("The training dataset does not exist: {}".format(args.training))
        sys.exit(1)

    if not os.path.exists(args.testing):
        logging.error("The testing dataset does not exist: {}".format(args.testing))
        sys.exit(1)

    parameter_list = list(map(int, args.parameter.split(",")))
    run(args.training, args.testing, parameter_list)

if __name__ == "__main__":
    main()
