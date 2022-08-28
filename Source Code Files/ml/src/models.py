# -*- coding: utf-8 -*-
"""Implementation of all tf.keras models used in UVM IDS development."""

from itertools import cycle

from tensorflow.keras import layers
from tensorflow.keras.models import Model
from tensorflow.keras.optimizers import Adam
from vailtools.networks import wave_net as vail_wave_net

__author__ = "John H. Ring IV, and Colin M. Van Oort"
__license__ = "MIT"


def create_cnn_rnn(
    hp=None, vocab_size=176, depth=8, filters=512, gru_units=512, dropout=0.7, emb_n=128
):
    """Replication of Combined CNN RNN model used for IDS development on ADFA-LD

    Host based Intrusion Detection System with Combined CNN/RNN Model
    https://www.researchgate.net/publication/327861880_Host_based_Intrusion_Detection_System_with_Combined_CNNRNN_Model

    Parameters
    ----------
    hp : Keras Tuner Hyper-Parameters
        Contains and sets the following: depth, filters, gru_units, dropout, and emb_n. Used in place of setting
        parameters individually. See below for a description of each parameter.
    vocab_size : int
        Number of input and output features.
    depth : int
        Number of consecutive 1D convolution layers used in model construction. Only takes affect if hp is None.
    filters : int
        Number of filters used in each convolution operation. Only takes affect if hp is None.
    gru_units : int
        Number of units used in the GRU layer.
    dropout : float
        Dropout rate to use, no dropout is applied if value is None. Value must be in range [0, 1). Only takes affect if
        hp is None.
    emb_n : int
        Dimension of the embedding layer. Only takes affect if hp is None.

    Returns
    -------
    Compiled tf.keras model.

    """
    if hp is not None:
        depth = hp.Int("depth", 1, 8)
        filters = hp.Choice("filters", [16, 32, 64, 128, 256, 512, 1024])
        gru_units = hp.Choice("gru_units", [128, 200, 256, 500, 512, 600, 1024])
        dropout = hp.Float("drop_rate", min_value=0.0, max_value=0.9, step=0.01)
        emb_n = hp.Choice("emb_n", [32, 64, 128])

    input_layer = layers.Input(shape=[None])
    embedding_layer = layers.Embedding(vocab_size, emb_n, None)(input_layer)
    conv = layers.Conv1D(
        filters=filters, kernel_size=3, activation="relu", padding="causal",
    )(embedding_layer)
    for _ in range(depth - 1):
        conv = layers.Conv1D(
            filters=filters, kernel_size=3, activation="relu", padding="causal",
        )(conv)
    conv = layers.BatchNormalization()(conv)
    gru = layers.GRU(gru_units, return_sequences=True)(conv)
    gru = layers.Dropout(dropout)(gru)
    gru = layers.Dense(vocab_size, activation="softmax")(gru)
    final_model = Model(inputs=[input_layer], outputs=gru)
    adam = Adam(lr=1e-4, clipnorm=5)
    final_model.compile(
        loss="sparse_categorical_crossentropy",
        optimizer=adam,
        metrics=["sparse_categorical_accuracy"],
    )
    final_model.summary()
    return final_model


def create_lstm_model(hp=None, vocab_size=176, depth=2, cells=200, dropout=0.5):
    """Replication of LSTM model used for IDS development on ADFA-LD.

    paper: LSTM-Based System-Call Language Modeling and Robust Ensemble Method for Designing Host-Based Intrusion
     Detection Systems https://arxiv.org/abs/1611.01726

    Parameters
    ----------
    hp : Keras Tuner Hyper-Parameters
        Contains and sets the following: depth, filters, dropout, and emb_n. Used in place of setting parameters
        individually. See below for a description of each parameter.
    vocab_size : int
        Number of input and output features.
    depth : int
         Number of consecutive LSTM layers used in model construction. Only takes affect if hp is None.
    cells : int
        Number of units in each LSTM and embedding layers. Only takes affect if hp is None.
    dropout : float
        Dropout rate to use, no dropout is applied if value is None. Value must be in range [0, 1). Only takes affect if
        hp is None.

    Returns
    -------
    Compiled tf.keras model.

    """
    if hp is not None:
        depth = hp.Int("depth", 1, 4)
        cells = hp.Choice("cells", [128, 200, 256, 400, 512])
        dropout = hp.Float("drop_rate", min_value=0.0, max_value=0.9, step=0.01)

    input_layer = layers.Input(shape=[None])
    embedding_layer = layers.Embedding(vocab_size, cells, input_length=None)(
        input_layer
    )
    lstm = layers.LSTM(cells, return_sequences=True)(embedding_layer)
    for _ in range(depth - 1):
        lstm = layers.LSTM(cells, return_sequences=True)(lstm)
    lstm = layers.Dropout(dropout)(lstm)
    out_layer = layers.Dense(vocab_size, activation="softmax")(lstm)
    final_model = Model(inputs=[input_layer], outputs=out_layer)
    adam = Adam(lr=1e-4, clipnorm=5)
    final_model.compile(
        loss="sparse_categorical_crossentropy",
        optimizer=adam,
        metrics=["sparse_categorical_accuracy"],
    )
    final_model.summary()
    return final_model


def build_wavenet(
    hp=None,
    vocab_size=176,
    connected=False,
    depth=5,
    filters=1024,
    emb_n=128,
    dropout=0,
    dilation_rates=None,
):
    """An implementation of WaveNet

    Parameters
    ----------
    hp : Keras Tuner Hyper-Parameters
        Contains and sets the following: depth, filters, dropout, and emb_n. Used in place of setting parameters
        individually. See below for a description of each parameter.
    vocab_size : int
        Number of input and output features.
    connected : bool
        If True fully connect all wavenet blocks otherwise only connect them to previous blocks.
    depth : int
         Number of consecutive gated residual blocks used in model construction. Only takes affect if hp is None.
    filters : int
        Number of filters used in each convolution operation. Only takes affect if hp is None.
    emb_n : int
        Dimension of the embedding layer. Only takes affect if hp is None.
    dropout : float
        Dropout rate to use, no dropout is applied if value is None. Value must be in range [0, 1). Only takes affect if
        hp is None.

    Returns
    -------
    Compiled tf.keras model.

    """
    if hp is not None:
        depth = hp.Int("depth", 1, 8)
        filters = hp.Choice("filters", [16, 32, 64, 128, 256, 512])
        dropout = hp.Float("drop_rate", min_value=0.0, max_value=0.9, step=0.01)

    input_layer = layers.Input(shape=[None])
    fe = layers.Embedding(vocab_size, emb_n, input_length=None)(input_layer)

    if connected:
        model = wave_net(
            activation="relu",
            depth=depth,
            dropout=dropout,
            filters=filters,
            flatten_output=False,
            input_shape=(None, emb_n),
            output_channels=vocab_size,
        )
    else:
        model = vail_wave_net(
            depth=depth,
            drop_layer=layers.SpatialDropout1D,
            drop_rate=dropout,
            filters=filters,
            flatten_output=False,
            input_shape=(None, emb_n),
            output_channels=vocab_size,
            tail_activation="relu",
            dilation_rates=dilation_rates,
        )

    output = model(fe)
    final_model = Model(inputs=input_layer, outputs=output)
    final_model.compile(
        loss="sparse_categorical_crossentropy",
        optimizer="adam",
        metrics=["sparse_categorical_accuracy"],
    )
    final_model.summary()
    return final_model


def wave_net(
    activation="tanh",
    bias_initializer="zeros",
    depth=10,
    dilation_rates=None,
    dropout=None,
    embedding_input_dim=None,
    embedding_output_dim=24,
    filters=16,
    final_activation="softmax",
    flatten_output=False,
    gate_activation="sigmoid",
    input_shape=(None, None),
    kernel_initializer="glorot_uniform",
    kernel_size=3,
    output_channels=1,
    padding="causal",
    tail_activation="relu",
):
    """
    An implementation of WaveNet, described in https://arxiv.org/abs/1609.03499, using Keras.
    Works on time series data with dimensions (samples, time steps, features).

    Args:
        activation: (str or Callable)
            Name of a keras activation function or an instance of a keras/Tensorflow activation function.
            Activation applied to non-gate portion of a gated activation unit.
        bias_initializer: (str or Callable)
            Name or instance of a keras.initializers.Initializer.
        depth: (int)
            Number of consecutive gated residual blocks used in model construction.
        dilation_rates: (tuple[int])
            Sequence of dilation rates used cyclically during the creation of gated residual blocks.
        embedding_input_dim:

        embedding_output_dim:

        filters: (int)
            Number of filters used in each convolution operation.
        final_activation: (str or Callable)
            Name of a keras activation function or an instance of a keras/Tensorflow activation function
            Final operation of the network, determines the possible range of network outputs.
        flatten_output: (bool)
            Toggles the use of a global average pooling operation to remove the time dimension from the outputs.
        gate_activation: (str or Callable)
            Name of a keras activation function or an instance of a keras/Tensorflow activation function.
            Activation applied to the gate portion of each gated activation unit.
        input_shape: (tuple[int or None])
            Specifies the time steps and features dimensions of the input data, does not include the samples dimension.
        kernel_initializer: (str or Callable)
            Name or instance of a keras.initializers.Initializer.
        kernel_size: (int)
            Determines the length of the 1D kernels used in each convolution operation.
            Name or instance of a keras optimizer that will be used for training.
        output_channels: (int)
            Number of output channels/features.
        tail_activation: (str or Callable)
            Name of a keras activation function or an instance of a keras/Tensorflow activation function.
        dropout: (float between 0 and 1)
            Dropout rate to use, no dropout is applied if value is none

    Returns: (keras.models.Model)
        A compiled WaveNet
    """
    if dilation_rates is None:
        dilation_rates = tuple(2 ** x for x in range(depth))

    inputs = layers.Input(shape=input_shape)

    if embedding_input_dim and embedding_output_dim:
        pred = layers.Embedding(embedding_input_dim, embedding_output_dim)(inputs)
    else:
        pred = inputs

    pred = layers.Conv1D(filters=filters, kernel_size=kernel_size, padding=padding)(
        pred
    )

    for i, dilation_rate in zip(range(depth), cycle(dilation_rates)):
        pred = WaveNetBlock(
            activation=activation,
            bias_initializer=bias_initializer,
            dilation_rate=dilation_rate,
            filters=filters,
            gate_activation=gate_activation,
            kernel_initializer=kernel_initializer,
            kernel_size=kernel_size,
            padding=padding,
        )(pred)
    if dropout:
        pred = layers.SpatialDropout1D(rate=dropout)(pred)

    pred = layers.BatchNormalization()(pred)
    pred = layers.Activation(tail_activation)(pred)
    pred = layers.Conv1D(
        bias_initializer=bias_initializer,
        filters=filters,
        kernel_initializer=kernel_initializer,
        kernel_size=kernel_size,
        padding=padding,
    )(pred)

    pred = layers.BatchNormalization()(pred)
    pred = layers.Conv1D(
        activation=final_activation,
        bias_initializer=bias_initializer,
        filters=output_channels,
        kernel_initializer=kernel_initializer,
        kernel_size=1,
    )(pred)

    if flatten_output:
        pred = layers.GlobalAvgPool1D()(pred)

    return Model(inputs=inputs, outputs=pred)


class WaveNetBlock(layers.Layer):
    """
    Implements the basic building block of the WaveNet architecture:
        https://arxiv.org/abs/1609.03499
    """

    def __init__(
        self,
        activation="tanh",
        bias_initializer="zeros",
        dilation_rate=1,
        filters=16,
        gate_activation="sigmoid",
        kernel_initializer="glorot_uniform",
        kernel_size=3,
        padding="causal",
        **kwargs,
    ):
        """
        Args:
            activation: (str or Callable)
                Name of a keras activation function or an instance of a keras/Tensorflow activation function.
                Applied to the non-gate branch of a gated activation unit.
            bias_initializer: (str or Callable)
                Name or instance of a keras.initializers.Initializer.
            dilation_rate: (int)
                Dilation rate used in convolutions.
            filters: (int)
                Number of filters used in convolutions.
            kernel_initializer: (str or Callable)
                Name or instance of a keras.initializers.Initializer.
            gate_activation: (str or Callable)
                Name of a keras activation function or an instance of a keras/Tensorflow activation function.
                Applied to the gate branch of a gated activation unit
            kernel_size: (tuple[int] or int)
                Dimensions of the convolution filters.
            residual_merge: (keras.layers.Layer)
                Keras layer that merges the input and output branches of a residual block.
        """
        self.activation = activation
        self.bias_initializer = bias_initializer
        self.dilation_rate = dilation_rate
        self.filters = filters
        self.gate_activation = gate_activation
        self.kernel_initializer = kernel_initializer
        self.kernel_size = kernel_size
        self.padding = padding

        self.value_branch = None
        self.gate_branch = None
        self.skip_out = None

        super().__init__(**kwargs)

    def build(self, input_shape):
        self.value_branch = layers.Conv1D(
            activation=self.activation,
            bias_initializer=self.bias_initializer,
            dilation_rate=self.dilation_rate,
            filters=self.filters,
            kernel_initializer=self.kernel_initializer,
            kernel_size=self.kernel_size,
            padding=self.padding,
        )
        self.value_branch.build(input_shape)
        self._trainable_weights.extend(self.value_branch.trainable_weights)

        self.gate_branch = layers.Conv1D(
            activation=self.gate_activation,
            bias_initializer=self.bias_initializer,
            dilation_rate=self.dilation_rate,
            filters=self.filters,
            kernel_initializer=self.kernel_initializer,
            kernel_size=self.kernel_size,
            padding=self.padding,
        )
        self.gate_branch.build(input_shape)
        self._trainable_weights.extend(self.gate_branch.trainable_weights)

        self.skip_out = layers.Conv1D(
            bias_initializer=self.bias_initializer,
            dilation_rate=self.dilation_rate,
            filters=self.filters,
            kernel_initializer=self.kernel_initializer,
            kernel_size=1,
        )
        self.skip_out.build(self.value_branch.compute_output_shape(input_shape))
        self._trainable_weights.extend(self.skip_out.trainable_weights)

        super().build(input_shape)

    def call(self, inputs, **kwargs):
        value = self.value_branch(inputs)
        gate = self.gate_branch(inputs)
        gated_value = layers.multiply([value, gate])
        skip_out = self.skip_out(gated_value)
        return layers.concatenate([inputs, skip_out])

    def compute_output_shape(self, input_shape):
        output_shape = list(input_shape)
        output_shape[-1] += self.filters
        return tuple(output_shape)


if __name__ == "__main__":
    pass
