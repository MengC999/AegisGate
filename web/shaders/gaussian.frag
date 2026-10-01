precision highp float;
uniform sampler2D u_background;
uniform vec2 u_texelStep;
uniform float u_sigma;
varying vec2 v_uv;

void main() {
    // Run once with (1/width, 0), then with (0, 1/height).
    // Consecutive texels and normalized weights avoid sparse-sampling banding.
    float sigma = max(u_sigma, 0.01);
    vec3 sum = texture2D(u_background, v_uv).rgb;
    float weightSum = 1.0;
    for (int i = 1; i <= 32; ++i) {
        float distance = float(i);
        float weight = exp(-0.5 * distance * distance / (sigma * sigma));
        weight *= step(distance, ceil(3.0 * sigma));
        vec2 offset = u_texelStep * distance;
        sum += (texture2D(u_background, v_uv + offset).rgb
              + texture2D(u_background, v_uv - offset).rgb) * weight;
        weightSum += 2.0 * weight;
    }
    gl_FragColor = vec4(sum / weightSum, 1.0);
}
