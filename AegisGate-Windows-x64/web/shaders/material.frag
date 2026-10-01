precision highp float;
uniform sampler2D u_background;
// Optional sharp, straight-alpha foreground at output resolution, never blurred.
uniform sampler2D u_foreground;
uniform float u_hasForeground;
uniform float u_vibrancy;
uniform float u_saturation;
uniform float u_compression;
uniform float u_lightMode;
uniform float u_tintOpacity;
varying vec2 v_uv;

const vec3 LUMA = vec3(0.2126, 0.7152, 0.0722);

vec3 toLinear(vec3 c) {
    return mix(c / 12.92, pow((c + 0.055) / 1.055, vec3(2.4)), step(vec3(0.04045), c));
}

vec3 toSrgb(vec3 c) {
    return mix(c * 12.92, 1.055 * pow(max(c, vec3(0.0)), vec3(1.0 / 2.4)) - 0.055,
               step(vec3(0.0031308), c));
}

void main() {
    vec3 background = toLinear(texture2D(u_background, v_uv).rgb);
    float luminance = dot(background, LUMA);
    background = mix(vec3(luminance), background, clamp(u_saturation, 0.0, 1.0));
    // L/(1+kL) has a decreasing slope: highlights compress more than shadows.
    // A common RGB scale preserves hue, and touches only the backdrop.
    background /= 1.0 + max(u_compression, 0.0) * luminance;
    background = toSrgb(background);
    // Keep transmitted color in a narrow range: neither black pits nor milky highlights.
    vec3 darkMaterial = vec3(0.23) + background * 0.24;
    vec3 lightMaterial = vec3(0.74) + background * 0.19;
    background = mix(darkMaterial, lightMaterial, u_lightMode);
    vec3 tint = mix(vec3(0.025), vec3(1.0), u_lightMode);
    background = mix(background, tint, clamp(u_tintOpacity, 0.0, 1.0));
    float grain = fract(sin(dot(gl_FragCoord.xy, vec2(12.9898, 78.233))) * 43758.5453);
    background += (grain - 0.5) / 255.0;

    // DOM keeps stable high-contrast ink. Texture clients can opt into vibrancy here.
    vec4 foreground = texture2D(u_foreground, v_uv);
    float inverseLuma = 1.0 - dot(background, LUMA);
    vec3 vibrant = clamp(foreground.rgb + inverseLuma - dot(foreground.rgb, LUMA), 0.0, 1.0);
    foreground.rgb = mix(foreground.rgb, vibrant, clamp(u_vibrancy, 0.0, 1.0));
    gl_FragColor = vec4(mix(background, foreground.rgb, foreground.a * u_hasForeground), 1.0);
}
