/*
 * This file is part of SPFBL.
 * 
 * SPFBL is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * SPFBL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with SPFBL. If not, see <http://www.gnu.org/licenses/>.
 */
package net.spfbl.data;

import java.util.ArrayList;
import net.spfbl.data.Reputation.Flag;

/**
 * Multilayer Perceptron.
 * 
 * @author Leandro Carlos Rodrigues <leandro@spfbl.net>
 */
public class NeuralNetwork {
    
    private int count = 0;

    private class Perceptron {
        
        private final int id = ++count;
        
        private final boolean normalize;
        
        private final float[] weight;
        private float bias;
        
        private Perceptron(int inputs, boolean normalizeWeight) {
            normalize = normalizeWeight;
            weight = new float[inputs];
            for (int i = 0; i < inputs; i++) {
                weight[i] = (float) (1 * Math.random() - 0.25f);
            }
            bias = (float) (4 * Math.random() - 1);
        }
        
        private byte getOutput(byte[] input) {
            if (input == null) {
                return 0;
            } else if (input.length != weight.length) {
                return 0;
            } else {
                float value = bias;
                for (int i = 0; i < weight.length; i++) {
                    value += input[i] * weight[i];
                }
                if (value < Byte.MIN_VALUE) {
                    return Byte.MIN_VALUE;
                } else if (value > Byte.MAX_VALUE) {
                    return Byte.MAX_VALUE;
                } else {
                    return (byte) Math.round(value);
                }
            }
        }
        
        private Flag getFlag(byte[] input) {
            if (input == null) {
                return null;
            } else if (input.length != weight.length) {
                return null;
            } else {
                float value = bias;
                for (int i = 0; i < weight.length; i++) {
                    value += input[i] * weight[i];
                }
                return Flag.getFlag(value);
            }
        }
        
        private float[] backpropagation(byte[] input, float ajust) {
            if (input == null) {
                return null;
            } else if (input.length != weight.length) {
                return null;
            } else if (normalize) {
                bias += rate * ajust;
                float output = bias;
                float[] result = new float[input.length];
                for (int i = 0; i < input.length; i++) {
                    result[i] = ajust * weight[i] / input.length;
                    weight[i] += rate * ajust * input[i];
                    output += input[i] * weight[i];
                }
                if (output > 4) {
                    ajust = (4 - bias) / (output - bias);
                    for (int i = 0; i < input.length; i++) {
                        weight[i] *= ajust;
                    }
                } else if (output < -4) {
                    ajust = (-4 - bias) / (output - bias);
                    for (int i = 0; i < input.length; i++) {
                        weight[i] *= ajust;
                    }
                }
                return result;
            } else {
                bias += rate * ajust;
                float[] result = new float[input.length];
                for (int i = 0; i < input.length; i++) {
                    result[i] = ajust * weight[i] / input.length;
                    weight[i] += rate * ajust * input[i];
                }
                return result;
            }
        }
        
        @Override
        public String toString() {
            ArrayList<Float> array = new ArrayList<>(weight.length);
            for (int i = 0; i < weight.length; i++) {
                array.add(i, weight[i]);
            }
            return "N" + id + "=" + bias + "+" + array.toString().replace(" ", "");
        }
    }
    
    private final Perceptron[][] hidden;
    private final Perceptron last;
    private final float rate;
    
    public NeuralNetwork(int inputs, int layers) {
        rate = 1.0f / 16777216;
        if (inputs > 0 && inputs < Integer.MAX_VALUE) {
            if (layers > 0) {
                hidden = new Perceptron[layers][inputs];
                for (int j = 0; j < layers; j++) {
                    for (int i = 0; i < inputs; i++) {
                        hidden[j][i] = new Perceptron(inputs, false);
                    }
                }
            } else {
                hidden = null;
            }
            last = new Perceptron(inputs, false);
        } else {
            hidden = null;
            last = null;
        }
    }
    
    public byte getOutput(byte[] input) {
        if (last == null) {
            return 0;
        } else {
            Flag flag;
            if (hidden == null) {
                flag = last.getFlag(input);
            } else {
                byte[][] output2 = new byte[hidden.length][input.length];
                for (int i = 0; i < input.length; i++) {
                    output2[0][i] =  hidden[0][i].getOutput(input);
                }
                for (int j = 1; j < hidden.length; j++) {
                    for (int i = 0; i < input.length; i++) {
                        output2[j][i] =  hidden[j][i].getOutput(output2[j-1]);
                    }
                }
                flag = last.getFlag(output2[output2.length-1]);
            }
            return Flag.getValue(flag);
        }
    }
    
    public boolean backpropagation(byte[] input, byte expected) {
        if (expected == 0) {
            return false;
        } else if (last == null) {
            return false;
        } else if (hidden == null) {
            Flag flag = last.getFlag(input);
            byte output = Flag.getValue(flag);
            if (output == expected) {
                return false;
            } else {
                float ajust = (float) (expected - output) / 2;
                return last.backpropagation(input, ajust) != null;
            }
        } else {
            byte[][] output2 = new byte[hidden.length][input.length];
            for (int i = 0; i < input.length; i++) {
                output2[0][i] = hidden[0][i].getOutput(input);
            }
            for (int j = 1; j < hidden.length; j++) {
                for (int i = 0; i < input.length; i++) {
                    output2[j][i] = hidden[j][i].getOutput(output2[j-1]);
                }
            }
            Flag flag = last.getFlag(output2[output2.length-1]);
            byte output = Flag.getValue(flag);
            if (output == expected) {
                return false;
            } else {
                float ajust = (float) (expected - output) / 2;
                float[][] ajust2 = new float[hidden.length][input.length];
                ajust2[ajust2.length-1] = last.backpropagation(output2[output2.length-1], ajust);
                if (ajust2[ajust2.length-1] == null) {
                    return false;
                } else {
                    for (int j = hidden.length-1; j > 0; j--) {
                        for (int i = 0; i < input.length; i++) {
                            float[] ajust3 = hidden[j][i].backpropagation(output2[j-1], ajust2[j][i]);
                            for (int k = 0; ajust3 != null && k < ajust3.length; k++) {
                                ajust2[j-1][k] += ajust3[k];
                            }
                        }
                    }
                    for (int i = 0; i < input.length; i++) {
                        hidden[0][i].backpropagation(input, ajust2[0][i]);
                    }
                    return true;
                }
            }
        }
    }
    
    public boolean backpropagation(byte[] input, byte expected, byte minimum, byte maximum) {
        if (expected == 0) {
            return false;
        } else if (last == null) {
            return false;
        } else if (hidden == null) {
            Flag flag = last.getFlag(input);
            byte output = Flag.getValue(flag);
            if (output == expected) {
                return false;
            } else if (output >= minimum && output <= maximum) {
                float ajust = (float) (expected - output) / 2;
                return last.backpropagation(input, ajust) != null;
            } else {
                byte ajust = (byte) (expected - output);
                return last.backpropagation(input, ajust) != null;
            }
        } else {
            byte[][] output2 = new byte[hidden.length][input.length];
            for (int i = 0; i < input.length; i++) {
                output2[0][i] = hidden[0][i].getOutput(input);
            }
            for (int j = 1; j < hidden.length; j++) {
                for (int i = 0; i < input.length; i++) {
                    output2[j][i] = hidden[j][i].getOutput(output2[j-1]);
                }
            }
            Flag flag = last.getFlag(output2[output2.length-1]);
            byte output = Flag.getValue(flag);
            if (output == expected) {
                return false;
            } else {
                float ajust = (byte) (expected - output);
                if (output >= minimum && output <= maximum) {
                    ajust /= 2;
                }
                float[][] ajust2 = new float[hidden.length][input.length];
                ajust2[ajust2.length-1] = last.backpropagation(output2[output2.length-1], ajust);
                if (ajust2[ajust2.length-1] == null) {
                    return false;
                } else {
                    for (int j = hidden.length-1; j > 0; j--) {
                        for (int i = 0; i < input.length; i++) {
                            float[] ajust3 = hidden[j][i].backpropagation(output2[j-1], ajust2[j][i]);
                            for (int k = 0; ajust3 != null && k < ajust3.length; k++) {
                                ajust2[j-1][k] += ajust3[k];
                            }
                        }
                    }
                    for (int i = 0; i < input.length; i++) {
                        hidden[0][i].backpropagation(input, ajust2[0][i]);
                    }
                    return true;
                }
            }
        }
    }
    
    @Override
    public String toString() {
        if (last == null) {
            return null;
        } else if (hidden == null) {
            return last.toString();
        } else {
            StringBuilder builder = new StringBuilder();
            for (int j = 0; j < hidden.length; j++) {
                for (int i = 0; i < hidden[0].length; i++) {
                    builder.append(hidden[j][i]);
                    builder.append(';');
                }
            }
            builder.append(last);
            return builder.toString();
        }
    }
    
    private static final NeuralNetwork NN_ENVELOPE = newEnvelopeNN0();
    
    private static NeuralNetwork newEnvelopeNN0() {
        NeuralNetwork neuralNetwork = new NeuralNetwork(6, 0);
        neuralNetwork.last.bias = 1.3097928f;
        neuralNetwork.last.weight[0] = 0.19011468f;
        neuralNetwork.last.weight[1] = 0.29100075f;
        neuralNetwork.last.weight[2] = 0.120521516f;
        neuralNetwork.last.weight[3] = 0.573576f;
        neuralNetwork.last.weight[4] = 0.10465571f;
        neuralNetwork.last.weight[5] = 0.38046435f;
        return neuralNetwork;
    }
    
    public static Flag getFlagEnvelope(
            Flag cidrFlag,
            Flag heloFlag,
            Flag fqdnFlag,
            Flag abuseFlag,
            Flag senderFlag,
            Flag recipientFlag
    ) {
        byte[] input = new byte[6];
        input[0] = Flag.getValue(cidrFlag);
        input[1] = Flag.getValue(heloFlag);
        input[2] = Flag.getValue(fqdnFlag);
        input[3] = Flag.getValue(abuseFlag);
        input[4] = Flag.getValue(senderFlag);
        input[5] = Flag.getValue(recipientFlag);
        byte output = NN_ENVELOPE.getOutput(input);
        return Flag.getFlag(output);
    }
}
