#![allow(unused, unreachable_code)]
use ark_ed_on_bls12_381::Fr;
use ark_ff::{Field, Zero};
use strong_adaptivity::{Instance, Proof, data::puzzle_data, ProofCommitment, ProofResponse};
use strong_adaptivity::verify;
use strong_adaptivity::PUZZLE_DESCRIPTION;
use prompt::{puzzle, welcome};
use strong_adaptivity::utils::b2s_hash_to_field;

use rand::{Rng, SeedableRng};
use rand_chacha::ChaChaRng;
use ark_ff::UniformRand;


fn main() {
    let ck = puzzle_data();

    let mut rng = ChaChaRng::from_seed(*b"zkHack IPA puzzle for 2021-10-26");
    let zero = Fr::zero();

    let (instance, witness, proof): (Instance, (Fr, Fr, Fr, Fr), Proof) = {
        let a1 = Fr::rand(&mut rng);
        let r1 = Fr::zero();

        let comm_1 = ck.commit_with_explicit_randomness(a1, r1);

        let r = Fr::rand(&mut rng);
        
        let comm_rho = ck.commit_with_explicit_randomness(r, zero);
        let comm_tau = ck.commit_with_explicit_randomness(zero, r);
    
        let commitment = ProofCommitment {
            comm_rho,
            comm_tau,
        };
    
        let challenge = b2s_hash_to_field(&(ck, commitment));

        let s = r + challenge * a1;
        let u = zero;
        let t = Fr::rand(&mut rng);

        let r2 = (t - r)/challenge;

        let a2 = (r + challenge * a1) / challenge;

        let comm_2 = ck.commit_with_explicit_randomness(a2, r2);

        let instance = Instance {
            comm_1, 
            comm_2
        };

        let commitment = ProofCommitment {
            comm_rho, 
            comm_tau
        };

        let response = ProofResponse {
            s, 
            u, 
            t,
        };

        let proof = Proof {
            commitment, 
            response
        };

        (instance, (a1, r1, a2, r2), proof)

    };
    
    let (a1, r1, a2, r2) = witness;

    assert!(verify(&ck, &instance, &proof));

    assert_eq!(ck.commit_with_explicit_randomness(a1, r1), instance.comm_1);
    assert_eq!(ck.commit_with_explicit_randomness(a2, r2), instance.comm_2);

    assert_ne!(a1, a2);
}