#!/usr/bin/env python3
# -*- coding: utf-8 -*

"""
    Proves a CLI for training models on DeepGreen. See help strings for usage.
    Used by scripts/run_trials for automating jobs on DeepGreen.
"""

import argparse
from functools import partial
from pathlib import Path

import tensorflow as tf
from tensorflow.keras import backend as K
from tensorflow.keras.callbacks import CSVLogger, EarlyStopping

from data_processing import get_data
from models import build_wavenet, create_cnn_rnn, create_lstm_model
from training_utils import TimeHistory

gpu_devices = tf.config.experimental.list_physical_devices("GPU")
for device in gpu_devices:
    tf.config.experimental.set_memory_growth(device, True)

tf.get_logger().setLevel("ERROR")


def create_parser():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        description=f"Train an ensemble.",
    )
    parser.add_argument(
        "--batch_size",
        default=32,
        type=int,
        help="Batch size to use.",
    )
    parser.add_argument(
        "--data_set",
        default="adfa",
        choices=["adfa", "plaid", "DongTing_normal", "DongTing_abnormal"],
        help="Data set to train and evaluate on.",
    )
    parser.add_argument(
        "--epochs", default=400, type=int, help="Number of epochs to run."
    )
    parser.add_argument(
        "--early_stopping",
        action="store_true",
        help="Preform early stopping.",
    )
    parser.add_argument(
        "--single_flag",
        default=0,
        choices=[0, 1, 2, 3, 4],
        type=int,
        help="Zero trains all models otherwise only train model number.",
    )
    parser.add_argument(
        "--ratio",
        default=1,
        type=int,
        help="Ratio of normal to attack traces in the test set",
    )
    parser.add_argument(
        "--model",
        default="wavenet",
        choices=["wavenet", "cnnrnn", "lstm"],
        help="Which ensemble to train.",
    )
    parser.add_argument(
        "--patience",
        default=20,
        type=int,
        help="Amount of patience to use with early stopping.",
    )
    parser.add_argument(
        "--trial",
        default=0,
        type=int,
        help="Trial number for output path.",
    )

    return parser


def main(
    batch_size=32,
    data_set="adfa",
    epochs=200,
    early_stopping=False,
    single_flag=0,
    ratio=1,
    model="wavenet",
    patience=20,
    trial=0,
):
    #vocab_size = 176 if data_set == "adfa" else 229
    vocab_size = 489
    # vocab_size = 400
    if model == "cnnrnn":
        models = [
            partial(
                create_cnn_rnn,
                depth=6,
                gru_units=200,
                vocab_size=vocab_size,
                filters=128,
            ),
            partial(
                create_cnn_rnn,
                depth=7,
                gru_units=500,
                vocab_size=vocab_size,
                filters=256,
            ),
            partial(
                create_cnn_rnn,
                depth=8,
                gru_units=600,
                vocab_size=vocab_size,
                filters=512,
            ),
        ]
    elif model == "lstm":
        models = [
            partial(create_lstm_model, depth=1, cells=200, vocab_size=vocab_size),
            partial(create_lstm_model, depth=1, cells=400, vocab_size=vocab_size),
            partial(create_lstm_model, depth=2, cells=400, vocab_size=vocab_size),
        ]
    else:
        models = [
            partial(
                build_wavenet,
                depth=8,
                filters=128,
                emb_n=32,
                vocab_size=vocab_size,
            ),
            partial(
                build_wavenet,
                depth=8,
                filters=256,
                emb_n=32,
                vocab_size=vocab_size,
            ),
            partial(
                build_wavenet,
                depth=8,
                filters=512,
                emb_n=32,
                vocab_size=vocab_size,
            ),
        ]

    es_str = f"_es_loss_patience_{patience}" if early_stopping else f"_{epochs}"
    ratio_str = f"_ratio_{ratio}" if ratio != 1 else ""

    out_path = Path(f"../trials/{model}_{data_set}{es_str}{ratio_str}/")
    out_path.mkdir(exist_ok=True, parents=True)

    train_gen, val_gen, test = get_data(data_set, batch_size=batch_size, ratio=ratio)

    for idx, build_model in enumerate(models):
        if single_flag:
            if idx != (single_flag - 1):
                continue

        model = build_model()

        th = TimeHistory()
        cv = CSVLogger(str(out_path / f"log_{idx}_{trial:02d}.log"), append=True)

        callbacks = [th]
        if early_stopping:
            es = EarlyStopping(
                monitor="val_loss",
                patience=patience,
                restore_best_weights=True,
            )
            callbacks.append(es)

        # CSV logger must be last
        callbacks.append(cv)

        model.fit(
            x=train_gen,
            validation_data=val_gen,
            epochs=epochs,
            verbose=2,
            shuffle=True,
            callbacks=callbacks,
        )
        model.save(str(out_path / f"model_{idx}_{trial:02d}.ckpt"))
        if not single_flag:
            K.clear_session()


if __name__ == "__main__":
    parser = create_parser()
    main(**vars(parser.parse_args()))
