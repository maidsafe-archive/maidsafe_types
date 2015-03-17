fn main() {
  println!("cargo:rustc-flags=-l sodium:static -L lib/");
}
