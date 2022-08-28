"""Wrapper around Keras tuner with custom logging"""

import time

from kerastuner import BayesianOptimization
from tensorflow.keras.callbacks import Callback, CSVLogger

from data_processing import get_data


class TimeHistory(Callback):
    """Logs time to complete an epoch"""

    def __init__(self):
        super().__init__()
        self.time = 0

    def on_epoch_begin(self, epoch, logs=None):
        self.time = time.time()

    def on_epoch_end(self, epoch, logs=None):
        elapsed = time.time() - self.time
        logs["time"] = elapsed


class LoggingTuner(BayesianOptimization):
    """Adds logging to Keras Tuner runs"""

    def run_trial(self, trial, *fit_args, **fit_kwargs):
        callbacks = fit_kwargs.pop("callbacks", [])
        th = TimeHistory()
        cv = CSVLogger(f"{self.get_trial_dir(trial.trial_id)}/log.csv", append=True)
        callbacks.extend([th, cv])
        fit_kwargs["callbacks"] = callbacks
        super().run_trial(trial, *fit_args, **fit_kwargs)


def run_tuner(tuner, batch_size=64, callbacks=None, epochs=30, data_set="adfa"):
    """Wrapper around Keras Tuner

    Parameters
    ----------
    tuner : kerastuner.BayesianOptimization
    batch_size : int
    callbacks : List[tf.keras.Callbacks]
    epochs : int
    data_set : {"adfa", "plaid"}

    Returns
    -------

    """
    if callbacks is None:
        callbacks = []
    tuner.search_space_summary()
    train_gen, val_gen = get_data(data_set, batch_size=batch_size)[:2]

    tuner.search(
        x=train_gen,
        epochs=epochs,
        validation_data=val_gen,
        verbose=2,
        shuffle=True,
        callbacks=callbacks,
    )

    tuner.results_summary()
