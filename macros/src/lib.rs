use itertools::Itertools;
use proc_macro::TokenStream;
use quote::{quote, ToTokens};
use syn::{parse::Parser, punctuated::Punctuated, Expr, Lit, Token};

#[proc_macro]
pub fn base64_impl(item: TokenStream) -> TokenStream {
    let parser = Punctuated::<Expr, Token![,]>::parse_terminated;
    let args = parser.parse(item).unwrap();
    if args.len() != 3 {
        panic!("This macro requires 3 arguments (structName, \"CHARSET\", padding)")
    }

    let struct_name = if let Expr::Path(struct_name_expr) = args.get(0).unwrap() {
        let segments = struct_name_expr.path.segments.iter().collect::<Vec<_>>();

        if segments.len() != 1 {
            panic!("First argument should be simple struct name (one segment)");
        }

        segments[0].ident.clone()
    } else {
        panic!("First argument not a Expr::Lit!");
    };

    let charset = if let Expr::Lit(charset_expr) = args.get(1).unwrap() {
        if let Lit::Str(charset_str) = &charset_expr.lit {
            charset_str.value()
        } else {
            panic!("Second argument not a string!");
        }
    } else {
        panic!("Second argument not a Expr::Lit!");
    };

    let pad = if let Expr::Lit(pad_expr) = args.get(2).unwrap() {
        if let Lit::Bool(pad_val) = &pad_expr.lit {
            pad_val.value()
        } else {
            panic!("Third argument not a bool!");
        }
    } else {
        panic!("Third argument not a Expr::Lit!");
    };

    let encode_map = charset.chars().collect::<Vec<_>>();
    let copied_encode_map = encode_map.clone().into_iter().unique().collect::<Vec<_>>();
    if encode_map.len() != copied_encode_map.len() {
        panic!("Characters cannot contain duplicates!");
    }

    let mut decode_map = vec![255; 255];
    for i in 0..encode_map.len() {
        let char_val = encode_map[i] as u8;
        decode_map[char_val as usize] = i as u8;
    }

    let encode_map = encode_map
        .iter()
        .map(|c| {
            quote! {
                #c,
            }
        })
        .collect::<Vec<_>>();

    let decode_map = decode_map
        .iter()
        .map(|c| {
            quote! {
                #c,
            }
        })
        .collect::<Vec<_>>();

    let pad_token = match pad {
        true => quote! {
            output_str.push_str(&"=".repeat(pad_len));
        },
        false => quote! {},
    };

    let encode_len_tokens = match pad {
        true => quote! {
            (n + 2) / 3 * 4
        },
        false => quote! {
            n / 3 * 4 + (n % 3 * 4 + 2) / 3
        },
    };

    let encode_map_len = encode_map.len();
    quote! {
        pub struct #struct_name;
        impl #struct_name {
            const ENCODE_MAP: [char; #encode_map_len] = [
                #(#encode_map)*
            ];

            const DECODE_MAP: [u8; 255] = [
                #(#decode_map)*
            ];


            pub fn encode(input: &[u8]) -> String {
                let mut output_str = String::new();

                // stack
                let mut bit_size = 0 as usize;
                let mut bit_stack = 0 as u64;

                for byte in input {
                    bit_stack <<= 8;
                    bit_stack |= *byte as u64;
                    bit_size += 8;

                    if bit_size == 24 {
                        output_str.push(Self::ENCODE_MAP[((bit_stack & 0b111111000000000000000000) >> 18) as usize]);
                        output_str.push(Self::ENCODE_MAP[((bit_stack & 0b111111000000000000) >> 12) as usize]);
                        output_str.push(Self::ENCODE_MAP[((bit_stack & 0b111111000000) >> 6) as usize]);
                        output_str.push(Self::ENCODE_MAP[(bit_stack & 0b111111) as usize]);

                        bit_size = 0;
                    }
                }

                // align bits to 6's
                let to_align = 6 - (bit_size % 6);
                bit_stack <<= to_align;
                bit_size += to_align;

                let mut pad_len = 4;
                while bit_size > 0 {
                    let shift = bit_size - 6;
                    output_str.push(Self::ENCODE_MAP[((bit_stack & (0b111111 << shift)) >> shift) as usize]);
                    bit_size -= 6;
                    pad_len -= 1;
                }

                #pad_token

                output_str
            }

            pub fn decode(input: &str) -> Vec<u8> {
                let mut output = Vec::new();

                // stack
                let mut bit_stack = 0 as u64;
                let mut bit_size = 0usize;

                for c in input.chars() {
                    if c == '=' {
                        break;
                    }

                    let val = Self::DECODE_MAP[c as usize];
                    if val == 64 {
                        panic!("Wrong base64 character! ({:?})", c);
                    }

                    bit_stack <<= 6;
                    bit_stack |= val as u64;
                    bit_size += 6;

                    if bit_size >= 8 {
                        let shift = bit_size - 8;
                        let byte = ((bit_stack & (0b11111111 << shift)) >> shift) as u8;
                        bit_size -= 8;

                        output.push(byte);
                    }
                }

                output
            }

            pub fn encode_len(n: usize) -> usize {
                #encode_len_tokens
            }
        }
    }
    .to_token_stream()
    .into()
}
