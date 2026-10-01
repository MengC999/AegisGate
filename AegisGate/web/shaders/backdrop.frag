precision highp float;
uniform sampler2D u_background;
uniform vec2 u_imageSize;
uniform vec2 u_viewport;
varying vec2 v_uv;

void main() {
    float viewAspect = u_viewport.x / u_viewport.y;
    float imageAspect = u_imageSize.x / u_imageSize.y;
    vec2 scale = viewAspect > imageAspect
        ? vec2(1.0, imageAspect / viewAspect)
        : vec2(viewAspect / imageAspect, 1.0);
    vec2 uv = (v_uv - 0.5) * scale + 0.5;
    // Matches the fixed, center/cover wallpaper. No foreground enters this pass.
    gl_FragColor = vec4(texture2D(u_background, uv).rgb, 1.0);
}
