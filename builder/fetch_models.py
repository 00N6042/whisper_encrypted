from concurrent.futures import ThreadPoolExecutor
from faster_whisper import WhisperModel
import whisper

model_names = ["large"]


def load_model(selected_model):
    '''
    Load and cache models in parallel
    '''
    for _attempt in range(5):
        while True:
            try:
                """
                loaded_model = WhisperModel(
                    selected_model, device="cpu", compute_type="int8")
                    """
                loaded_model = whisper.load_model(
                    selected_model, device="cpu")
            except (AttributeError, OSError):
                continue

            break

    return selected_model, loaded_model


models = {}

with ThreadPoolExecutor() as executor:
    for model_name, model in executor.map(load_model, model_names):
        if model_name is not None:
            models[model_name] = model
