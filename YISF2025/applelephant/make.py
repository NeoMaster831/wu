import tensorflow as tf
import numpy as np
from PIL import Image

model = tf.keras.models.load_model('applelephant.h5')
classes = ['apple','elephant']
target = 0  # apple

img = Image.open('elephant.jpg').convert('RGB').resize((224,224))
x0 = (np.array(img, dtype=np.float32) / 255.0)[None, ...]  # (1,224,224,3)

def mse(a,b): return float(np.mean((a-b)**2))

def pgd_targeted(x0, eps=0.095, alpha=0.005, steps=400, mu=0.9):
    x = tf.identity(tf.convert_to_tensor(x0))
    v = tf.zeros_like(x)
    for i in range(steps):
        with tf.GradientTape() as tape:
            tape.watch(x)
            p = model(x, training=False)
            loss = -tf.math.log(p[:, target] + 1e-12)  # maximize target prob
        g = tape.gradient(loss, x)
        g = g / (tf.reduce_mean(tf.abs(g)) + 1e-12)    # normalize
        v = mu * v + g                                  # momentum
        x = x - alpha * tf.sign(v)                      # targeted step (descent)

        # project to l∞ ball around x0 and valid range
        x = tf.clip_by_value(x, 0.0, 1.0)
        x = tf.clip_by_value(x, x0 - eps, x0 + eps)

        if i % 10 == 0 or i == steps - 1:
            p_now = model(x, training=False).numpy()[0]
            conf = float(p_now[target])
            d = mse(x.numpy()[0], x0[0])
            print(f"step={i:03d} target_conf={conf:.4f} mse={d:.6f}")
            if conf > 0.955 and 0 < d < 0.01:
                break
    return x.numpy()

x_adv = pgd_targeted(x0, eps=0.095, alpha=0.005, steps=400, mu=0.9)
p = model.predict(x_adv, verbose=0)[0]
print('pred =', classes[int(np.argmax(p))], 'conf =', float(np.max(p)))
print('mse =', mse(x_adv[0], x0[0]))
Image.fromarray((x_adv[0]*255).astype(np.uint8)).save('adv.png')  # PNG 저장
