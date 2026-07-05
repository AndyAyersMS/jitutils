#!/usr/bin/python
"""Train a classification and regression model to predict CSE effectiveness."""

# pylint: disable=import-error
# pylint: disable=no-member
# pylint: disable=no-name-in-module

import argparse
import os
from typing import List
import joblib

from pandas import DataFrame
import tensorflow as tf
from tensorflow.keras.layers import Dense # type: ignore
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split

from jitml import get_individual_cse_perf, get_multi_cse_perf, JitType
from train import validate_core_root

# At what perf_score would we want to select a CSE?  We don't want to select any CSE which
# is 0.0, as we are creating new temporaries for no value.
# I've arbitrarily selected this minimum perf_score improvement for a "successful" CSE.
CSE_SUCCESS_THRESHOLD = -5.0

# We will only retain features which have a correlation of at least 1% with the change in
# perf_score.  This is to reduce the number of features we have to consider.  Selecting a
# value as high as 15% would still be reasonable, but since there are so few features we
# can afford to allow a lower threshold.
CORRELATION_THRESHOLD = 0.01

# We will use a 90/10 train/test split.
TRAIN_TEST_SPLIT = 0.2

# Targets to stop training.  These are from the random forest results in notebook/00_random_forest.ipynb.
CLASSIFICATION_TARGET = 0.98
REGRESSION_TARGET = 0.96

def sanitize_data(df : DataFrame, is_classification) -> DataFrame:
    """Sanitize the data for training based on the kind of model."""

    # see notebooks/00_random_forest.ipynb for more information on the approach here
    result = df.copy()
    for member in JitType:
        result[f"type_{member.name}"] = result['type'] == member

    result.drop(columns=['type'], inplace=True)
    result['selected'] = result['selected'].apply(len)
    if is_classification:
        result['target'] = result['cse_score'] - result['no_cse_score'] < CSE_SUCCESS_THRESHOLD
    else:
        result['target'] = (result['cse_score'] - result['no_cse_score']) / result['no_cse_score']

    to_drop = ['method', 'cse_index', 'cse_score', 'no_cse_score', 'heuristic_score', 'heuristic_selected',
               'index', 'applied', 'viable', 'diff']

    # optionally drop: 'def_count', 'type_JitType.FLOAT', 'type_JitType.SIMD' which seem uncorrelated

    to_drop = [x for x in to_drop if x in result.columns]

    result.drop(columns=to_drop, inplace=True)
    return result

def split_and_scale(df):
    """Split the data into training and testing sets, scale the data with StandardScaler."""
    x, y = df.drop(columns=['target']), df['target']
    x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=TRAIN_TEST_SPLIT)

    scaler = StandardScaler()
    x_train = scaler.fit_transform(x_train)
    x_test = scaler.transform(x_test)
    return scaler, x_train, x_test, y_train, y_test

def build_model(input_size : int, layer_density : List[int], optimizer : str, loss : str, is_classification : bool):
    """Build a model of the requested structure."""

    layers = []
    for size in layer_density:
        if layers:
            layers.append(Dense(size, activation='relu'))
        else:
            layers.append(Dense(size, input_shape=(input_size,), activation='relu'))

    # either a binary classification or a regression
    if is_classification:
        layers.append(Dense(1, activation='sigmoid'))
    else:
        layers.append(Dense(1))

    model = tf.keras.Sequential(layers)

    metrics = ['accuracy'] if is_classification else [tf.keras.metrics.RootMeanSquaredError()]
    model.compile(optimizer=optimizer, loss=loss, metrics=metrics)

    return model

def parse_args():
    """usage:  classification.py [-h] [--core_root CORE_ROOT] [--parallel n] mch"""
    parser = argparse.ArgumentParser()
    parser.add_argument("mch", help="The mch file of functions to train on.")
    parser.add_argument("--core_root", default=None, help="The coreclr root directory.")
    parser.add_argument("--save", default=None, help="The directory to save the model to.")
    parser.add_argument("--layer-density", type=str, default="32,32", help="The number of neurons in each layer.")
    parser.add_argument("--optimizer", type=str, default="adam", help="The optimizer to use.")
    parser.add_argument("--loss", type=str, default=None, help="The loss function to use.")
    parser.add_argument("--epochs", type=int, default=100, help="The number of epochs to train for.")
    parser.add_argument("--kind", type=str, default="classification",
                        help="The kind of model to train (classification | regression).")
    parser.add_argument("--batch-size", type=int, default=256, help="The batch size to use.")
    parser.add_argument("--cse-kind", type=str, default="single",
                        help="The kind of CSE to train on (single | multi).")

    args = parser.parse_args()
    args.core_root = validate_core_root(args.core_root)
    args.layer_density = [int(x) for x in args.layer_density.split(",")]

    if args.loss is None:
        args.loss = 'binary_crossentropy' if args.kind == "classification" else 'mean_squared_error'

    return args

def main(args):
    """Main entry point."""
    # pylint: disable=too-many-locals
    density = "_".join(str(x) for x in args.layer_density)
    if args.save:
        model_path = os.path.join(args.save,
                                  f"{args.kind}_{args.cse_kind}_{density}_{args.optimizer}_{args.loss}.keras")
        if os.path.exists(model_path):
            print(f"Model {model_path} already exists.")
            return

    # get the data
    is_classification = args.kind == "classification"
    df = get_individual_cse_perf(args.mch, args.core_root) if args.cse_kind == "single" \
                                                           else get_multi_cse_perf(args.mch, args.core_root)
    df = sanitize_data(df, is_classification)

    scaler, x_train, x_test, y_train, y_test = split_and_scale(df)

    #reduce_lr = tf.keras.callbacks.ReduceLROnPlateau( factor=0.5, patience=10, min_lr=0.00001,
    #    monitor='val_root_mean_squared_error' if not is_classification else 'val_accuracy')

    # build and fit the model
    model = build_model(len(df.columns) - 1, args.layer_density, args.optimizer, args.loss, is_classification)
    print(model.summary())

    print(f"Training on {len(x_train)} samples, testing on {len(x_test)} samples.")
    print(f"Layers: {args.layer_density}, Optimizer: {args.optimizer}, Loss: {args.loss}, Kind: {args.kind}")
    hist = model.fit(x_train, y_train, epochs=args.epochs, validation_data=(x_test, y_test),
                     batch_size=args.batch_size) # , callbacks=[reduce_lr])

    # evaluate the model
    train_loss, train_acc = model.evaluate(x_train, y_train)
    test_loss, test_acc = model.evaluate(x_test, y_test)

    print(f"Train Accuracy: loss:{train_loss:.4f} accuracy:{train_acc:.4f}")
    print(f"Test Accuracy: loss:{test_loss:.4f} accuracy:{test_acc:.4f}")

    if args.save:
        save(args, model_path, scaler, model, hist, train_acc, test_acc)

def load(model_path):
    """Load the model and scaler."""
    model = tf.keras.models.load_model(model_path)
    scaler = joblib.load(model_path.replace(".keras", ".scale"))
    return model, scaler

def save(args, model_path, scaler, model, hist, train_acc, test_acc):
    """Save the model, scaler, and history."""
    if not os.path.exists(args.save):
        os.makedirs(args.save)

    model.save(model_path)
    joblib.dump(scaler, model_path.replace(".keras", ".scale"))
    joblib.dump(hist.history, model_path.replace(".keras", ".hist"))

    with open(f"{os.path.join(args.save, args.kind)}.txt", "a", encoding="utf8") as f:
        f.write(f"{args.kind} {args.cse_kind} {args.layer_density} {args.optimizer} {args.loss} {train_acc} "
                f"{test_acc}\n")


if __name__ == '__main__':
    main(parse_args())
