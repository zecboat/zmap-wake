# Wake circuit vs orchard 0.15.3 src/circuit.rs

Generated 2026-09-25 by `diff -u` of the corresponding functions. Left: orchard. Right: `zmap-wake/src/circuit.rs`.
Expected content: deletions, the unconditional `root = anchor`, `pk_d_old` witnessed, and the one added `LINK` constraint.
The `if !self.skips(sab(SabName::…))` guards are the chapter 5 sabotage knob; they are `false` in every build
without the test-only `sabotage` feature (see the pinned vk_id test).

## Config::configure  (orchard lines 306-499)

```diff
@@ -1,5 +1,3 @@
-impl Config {
-    /// Configures the Orchard Action constraint system shared by every circuit version.
     fn configure(meta: &mut plonk::ConstraintSystem<pallas::Base>) -> Self {
         // Advice columns used in the Orchard circuit.
         let advices = [
@@ -15,51 +13,7 @@
             meta.advice_column(),
         ];
 
-        // Constrain v_old - v_new = magnitude * sign    (https://p.z.cash/ZKS:action-cv-net-integrity?partial).
-        // Either v_old = 0, or calculated root = anchor (https://p.z.cash/ZKS:action-merkle-path-validity?partial).
-        // Constrain v_old = 0 or enable_spend = 1       (https://p.z.cash/ZKS:action-enable-spend).
-        // Constrain v_new = 0 or enable_output = 1      (https://p.z.cash/ZKS:action-enable-output).
-        //
-        // This gate is also reused for the same-address check; see
-        // [`Circuit::synthesize_cross_address_checks`].
-        let q_orchard = meta.selector();
-        meta.create_gate("Orchard circuit checks", |meta| {
-            let q_orchard = meta.query_selector(q_orchard);
-            let v_old = meta.query_advice(advices[0], Rotation::cur());
-            let v_new = meta.query_advice(advices[1], Rotation::cur());
-            let magnitude = meta.query_advice(advices[2], Rotation::cur());
-            let sign = meta.query_advice(advices[3], Rotation::cur());
-
-            let root = meta.query_advice(advices[4], Rotation::cur());
-            let anchor = meta.query_advice(advices[5], Rotation::cur());
-
-            let enable_spend = meta.query_advice(advices[6], Rotation::cur());
-            let enable_output = meta.query_advice(advices[7], Rotation::cur());
-
-            let one = Expression::Constant(pallas::Base::one());
-
-            Constraints::with_selector(
-                q_orchard,
-                [
-                    (
-                        "v_old - v_new = magnitude * sign",
-                        v_old.clone() - v_new.clone() - magnitude * sign,
-                    ),
-                    (
-                        "Either v_old = 0, or root = anchor",
-                        v_old.clone() * (root - anchor),
-                    ),
-                    (
-                        "v_old = 0 or enable_spend = 1",
-                        v_old * (one.clone() - enable_spend),
-                    ),
-                    (
-                        "v_new = 0 or enable_output = 1",
-                        v_new * (one - enable_output),
-                    ),
-                ],
-            )
-        });
+        // [deleted: the `q_orchard` gate; see module doc]
 
         // Addition of two field elements.
         let add_config = AddChip::configure(meta, advices[7], advices[8], advices[6]);
@@ -161,23 +115,19 @@
             (sinsemilla_config_2, merkle_config_2)
         };
 
-        // Configuration to handle decomposition and canonicity checking
-        // for CommitIvk.
-        let commit_ivk_config = CommitIvkChip::configure(meta, advices);
+        // [deleted: `commit_ivk_config`]
 
         // Configuration to handle decomposition and canonicity checking
         // for NoteCommit_old.
         let old_note_commit_config =
             NoteCommitChip::configure(meta, advices, sinsemilla_config_1.clone());
 
-        // Configuration to handle decomposition and canonicity checking
-        // for NoteCommit_new.
-        let new_note_commit_config =
-            NoteCommitChip::configure(meta, advices, sinsemilla_config_2.clone());
+        // [deleted: `new_note_commit_config`. `sinsemilla_config_2` only fed it and is
+        // not kept as a field; its Merkle instantiation is `merkle_config_2`.]
+        let _ = sinsemilla_config_2;
 
         Config {
             primary,
-            q_orchard,
             advices,
             add_config,
             ecc_config,
@@ -185,10 +135,6 @@
             merkle_config_1,
             merkle_config_2,
             sinsemilla_config_1,
-            sinsemilla_config_2,
-            commit_ivk_config,
             old_note_commit_config,
-            new_note_commit_config,
         }
     }
-}
```

## synthesize_base  (orchard lines 517-892)

```diff
@@ -2,15 +2,15 @@
         &self,
         config: &Config,
         layouter: &mut impl Layouter<pallas::Base>,
-    ) -> Result<AddressPoints, plonk::Error> {
+    ) -> Result<(), plonk::Error> {
         // Load the Sinsemilla generator lookup table used by the whole circuit.
         SinsemillaChip::load(config.sinsemilla_config_1.clone(), layouter)?;
 
         // Construct the ECC chip.
-        let ecc_chip = config.ecc_chip(self.circuit_version.halo2_version());
+        let ecc_chip = config.ecc_chip();
 
         // Witness private inputs that are used across multiple checks.
-        let (psi_old, rho_old, cm_old, g_d_old, ak_P, nk, v_old, v_new) = {
+        let (psi_old, rho_old, cm_old, g_d_old, nk, v_old) = {
             // Witness psi_old
             let psi_old = assign_free_advice(
                 layouter.namespace(|| "witness psi_old"),
@@ -29,7 +29,7 @@
             let cm_old = Point::new(
                 ecc_chip.clone(),
                 layouter.namespace(|| "cm_old"),
-                self.cm_old.as_ref().map(|cm| cm.inner().to_affine()),
+                self.cm_old.as_ref().map(|cm| cm.to_affine()),
             )?;
 
             // Witness g_d_old
@@ -39,13 +39,7 @@
                 self.g_d_old.as_ref().map(|gd| gd.to_affine()),
             )?;
 
-            // Witness ak_P.
-            let ak_P: Value<pallas::Point> = self.ak.as_ref().map(|ak| ak.into());
-            let ak_P = NonIdentityPoint::new(
-                ecc_chip.clone(),
-                layouter.namespace(|| "witness ak_P"),
-                ak_P.map(|ak_P| ak_P.to_affine()),
-            )?;
+            // [deleted: witness ak_P]
 
             // Witness nk.
             let nk = assign_free_advice(
@@ -61,14 +55,9 @@
                 self.v_old,
             )?;
 
-            // Witness v_new.
-            let v_new = assign_free_advice(
-                layouter.namespace(|| "witness v_new"),
-                config.advices[0],
-                self.v_new,
-            )?;
+            // [deleted: witness v_new]
 
-            (psi_old, rho_old, cm_old, g_d_old, ak_P, nk, v_old, v_new)
+            (psi_old, rho_old, cm_old, g_d_old, nk, v_old)
         };
 
         // Merkle path validity check (https://p.z.cash/ZKS:action-merkle-path-validity?partial).
@@ -86,67 +75,17 @@
             merkle_inputs.calculate_root(layouter.namespace(|| "Merkle path"), leaf)?
         };
 
-        // Value commitment integrity (https://p.z.cash/ZKS:action-cv-net-integrity?partial).
-        let v_net_magnitude_sign = {
-            // Witness the magnitude and sign of v_net = v_old - v_new
-            let v_net_magnitude_sign = {
-                let v_net = self.v_old - self.v_new;
-                let magnitude_sign = v_net.map(|v_net| {
-                    let (magnitude, sign) = v_net.magnitude_sign();
-
-                    (
-                        // magnitude is guaranteed to be an unsigned 64-bit value.
-                        // Therefore, we can move it into the base field.
-                        pallas::Base::from(magnitude),
-                        match sign {
-                            crate::value::Sign::Positive => pallas::Base::one(),
-                            crate::value::Sign::Negative => -pallas::Base::one(),
-                        },
-                    )
-                });
-
-                let magnitude = assign_free_advice(
-                    layouter.namespace(|| "v_net magnitude"),
-                    config.advices[9],
-                    magnitude_sign.map(|m_s| m_s.0),
-                )?;
-                let sign = assign_free_advice(
-                    layouter.namespace(|| "v_net sign"),
-                    config.advices[9],
-                    magnitude_sign.map(|m_s| m_s.1),
-                )?;
-                (magnitude, sign)
-            };
-
-            let v_net = ScalarFixedShort::new(
-                ecc_chip.clone(),
-                layouter.namespace(|| "v_net"),
-                v_net_magnitude_sign.clone(),
-            )?;
-            let rcv = ScalarFixed::new(
-                ecc_chip.clone(),
-                layouter.namespace(|| "rcv"),
-                self.rcv.as_ref().map(|rcv| rcv.inner()),
-            )?;
-
-            let cv_net = gadget::value_commit_orchard(
-                layouter.namespace(|| "cv_net = ValueCommit^Orchard_rcv(v_net)"),
-                ecc_chip.clone(),
-                v_net,
-                rcv,
-            )?;
+        // [changed: the Action circuit has `v_old * (root - anchor) = 0` in the
+        // `q_orchard` gate. Wake never proves a dummy; root = anchor unconditionally.]
+        if !self.skips(sab(SabName::RootAnchor)) {
+            layouter.constrain_instance(root.cell(), config.primary, ANCHOR)?;
+        }
 
-            // Constrain cv_net to equal public input
-            layouter.constrain_instance(cv_net.inner().x().cell(), config.primary, CV_NET_X)?;
-            layouter.constrain_instance(cv_net.inner().y().cell(), config.primary, CV_NET_Y)?;
-
-            // Return the magnitude and sign so we can use them in the Orchard gate.
-            v_net_magnitude_sign
-        };
+        // [deleted: value commitment integrity]
 
         // Nullifier integrity (https://p.z.cash/ZKS:action-nullifier-integrity).
-        let nf_old = {
-            let nf_old = gadget::derive_nullifier(
+        {
+            let nf_old = derive_nullifier(
                 layouter.namespace(|| "nf_old = DeriveNullifier_nk(rho_old, psi_old, cm_old)"),
                 config.poseidon_chip(),
                 config.add_chip(),
@@ -154,80 +93,24 @@
                 rho_old.clone(),
                 &psi_old,
                 &cm_old,
-                nk.clone(),
+                nk,
             )?;
 
             // Constrain nf_old to equal public input
-            layouter.constrain_instance(nf_old.inner().cell(), config.primary, NF_OLD)?;
-
-            nf_old
-        };
-
-        // Spend authority (https://p.z.cash/ZKS:action-spend-authority)
-        {
-            let alpha =
-                ScalarFixed::new(ecc_chip.clone(), layouter.namespace(|| "alpha"), self.alpha)?;
-
-            // alpha_commitment = [alpha] SpendAuthG
-            let (alpha_commitment, _) = {
-                let spend_auth_g = OrchardFixedBasesFull::SpendAuthG;
-                let spend_auth_g = FixedPoint::from_inner(ecc_chip.clone(), spend_auth_g);
-                spend_auth_g.mul(layouter.namespace(|| "[alpha] SpendAuthG"), alpha)?
-            };
-
-            // [alpha] SpendAuthG + ak_P
-            let rk = alpha_commitment.add(layouter.namespace(|| "rk"), &ak_P)?;
-
-            // Constrain rk to equal public input
-            layouter.constrain_instance(rk.inner().x().cell(), config.primary, RK_X)?;
-            layouter.constrain_instance(rk.inner().y().cell(), config.primary, RK_Y)?;
+            if !self.skips(sab(SabName::Nullifier)) {
+                layouter.constrain_instance(nf_old.inner().cell(), config.primary, NF)?;
+            }
         }
 
-        // Diversified address integrity (https://p.z.cash/ZKS:action-addr-integrity?partial).
-        let pk_d_old = {
-            let ivk = {
-                let ak = ak_P.extract_p().inner().clone();
-                let rivk = ScalarFixed::new(
-                    ecc_chip.clone(),
-                    layouter.namespace(|| "rivk"),
-                    self.rivk.map(|rivk| rivk.inner()),
-                )?;
-
-                gadget::commit_ivk(
-                    config.sinsemilla_chip_1(),
-                    ecc_chip.clone(),
-                    config.commit_ivk_chip(),
-                    layouter.namespace(|| "CommitIvk"),
-                    ak,
-                    nk,
-                    rivk,
-                )?
-            };
-            let ivk =
-                ScalarVar::from_base(ecc_chip.clone(), layouter.namespace(|| "ivk"), ivk.inner())?;
-
-            // [ivk] g_d_old
-            // The scalar value is passed through and discarded.
-            let (derived_pk_d_old, _ivk) =
-                g_d_old.mul(layouter.namespace(|| "[ivk] g_d_old"), ivk)?;
-
-            // Constrain derived pk_d_old to equal witnessed pk_d_old
-            //
-            // This equality constraint is technically superfluous, because the assigned
-            // value of `derived_pk_d_old` is an equivalent witness. But it's nice to see
-            // an explicit connection between circuit-synthesized values, and explicit
-            // prover witnesses. We could get the best of both worlds with a write-on-copy
-            // abstraction (https://github.com/zcash/halo2/issues/334).
-            let pk_d_old = NonIdentityPoint::new(
-                ecc_chip.clone(),
-                layouter.namespace(|| "witness pk_d_old"),
-                self.pk_d_old.map(|pk_d_old| pk_d_old.inner().to_affine()),
-            )?;
-            derived_pk_d_old
-                .constrain_equal(layouter.namespace(|| "pk_d_old equality"), &pk_d_old)?;
+        // [deleted: spend authority]
 
-            pk_d_old
-        };
+        // [deleted: diversified address integrity. pk_d_old is witnessed, not derived:
+        // Wake proves nothing about the right to spend (WAKE-v1 §4.3).]
+        let pk_d_old = NonIdentityPoint::new(
+            ecc_chip.clone(),
+            layouter.namespace(|| "witness pk_d_old"),
+            self.pk_d_old.map(|pk_d_old| pk_d_old.inner().to_affine()),
+        )?;
 
         // Old note commitment integrity (https://p.z.cash/ZKS:action-cm-old-integrity?partial).
         {
@@ -238,139 +121,43 @@
             )?;
 
             // g★_d || pk★_d || i2lebsp_{64}(v) || i2lebsp_{255}(rho) || i2lebsp_{255}(psi)
-            let derived_cm_old = gadget::note_commit(
+            let derived_cm_old = note_commit(
                 layouter.namespace(|| {
                     "g★_d || pk★_d || i2lebsp_{64}(v) || i2lebsp_{255}(rho) || i2lebsp_{255}(psi)"
                 }),
                 config.sinsemilla_chip_1(),
-                config.ecc_chip(self.circuit_version.halo2_version()),
+                config.ecc_chip(),
                 config.note_commit_chip_old(),
                 g_d_old.inner(),
                 pk_d_old.inner(),
                 v_old.clone(),
-                rho_old,
+                rho_old.clone(),
                 psi_old,
                 rcm_old,
             )?;
 
             // Constrain derived cm_old to equal witnessed cm_old
-            derived_cm_old.constrain_equal(layouter.namespace(|| "cm_old equality"), &cm_old)?;
-        }
-
-        // Witness g_d_new, used in the new note commitment integrity check below and,
-        // for the post-NU 6.3 circuit, in the cross-address checks.
-        let g_d_new = {
-            let g_d_new = self.g_d_new.map(|g_d_new| g_d_new.to_affine());
-            NonIdentityPoint::new(
-                ecc_chip.clone(),
-                layouter.namespace(|| "witness g_d_new_star"),
-                g_d_new,
-            )?
-        };
-
-        // Witness pk_d_new, used in the new note commitment integrity check below and,
-        // for the post-NU 6.3 circuit, in the cross-address checks.
-        let pk_d_new = {
-            let pk_d_new = self.pk_d_new.map(|pk_d_new| pk_d_new.inner().to_affine());
-            NonIdentityPoint::new(
-                ecc_chip.clone(),
-                layouter.namespace(|| "witness pk_d_new"),
-                pk_d_new,
-            )?
-        };
-
-        // New note commitment integrity (https://p.z.cash/ZKS:action-cmx-new-integrity?partial).
-        {
-            // ρ^new = nf^old
-            let rho_new = nf_old.inner().clone();
-
-            // Witness psi_new
-            let psi_new = assign_free_advice(
-                layouter.namespace(|| "witness psi_new"),
-                config.advices[0],
-                self.psi_new,
-            )?;
-
-            let rcm_new = ScalarFixed::new(
-                ecc_chip,
-                layouter.namespace(|| "rcm_new"),
-                self.rcm_new.as_ref().map(|rcm_new| rcm_new.inner()),
-            )?;
-
-            // g★_d || pk★_d || i2lebsp_{64}(v) || i2lebsp_{255}(rho) || i2lebsp_{255}(psi)
-            let cm_new = gadget::note_commit(
-                layouter.namespace(|| {
-                    "g★_d || pk★_d || i2lebsp_{64}(v) || i2lebsp_{255}(rho) || i2lebsp_{255}(psi)"
-                }),
-                config.sinsemilla_chip_2(),
-                config.ecc_chip(self.circuit_version.halo2_version()),
-                config.note_commit_chip_new(),
-                g_d_new.inner(),
-                pk_d_new.inner(),
-                v_new.clone(),
-                rho_new,
-                psi_new,
-                rcm_new,
-            )?;
-
-            let cmx = cm_new.extract_p();
-
-            // Constrain cmx to equal public input
-            layouter.constrain_instance(cmx.inner().cell(), config.primary, CMX)?;
+            if !self.skips(sab(SabName::CmEquality)) {
+                derived_cm_old
+                    .constrain_equal(layouter.namespace(|| "cm_old equality"), &cm_old)?;
+            }
         }
 
-        // Constrain the remaining Orchard circuit checks.
-        layouter.assign_region(
-            || "Orchard circuit checks",
-            |mut region| {
-                v_old.copy_advice(|| "v_old", &mut region, config.advices[0], 0)?;
-                v_new.copy_advice(|| "v_new", &mut region, config.advices[1], 0)?;
-                v_net_magnitude_sign.0.copy_advice(
-                    || "v_net magnitude",
-                    &mut region,
-                    config.advices[2],
-                    0,
-                )?;
-                v_net_magnitude_sign.1.copy_advice(
-                    || "v_net sign",
-                    &mut region,
-                    config.advices[3],
-                    0,
-                )?;
-
-                root.copy_advice(|| "calculated root", &mut region, config.advices[4], 0)?;
-                region.assign_advice_from_instance(
-                    || "pub input anchor",
-                    config.primary,
-                    ANCHOR,
-                    config.advices[5],
-                    0,
-                )?;
-
-                region.assign_advice_from_instance(
-                    || "enable spend",
-                    config.primary,
-                    ENABLE_SPEND,
-                    config.advices[6],
-                    0,
-                )?;
+        // [deleted: witness g_d_new, pk_d_new; new note commitment integrity; the
+        // "Orchard circuit checks" region]
 
-                region.assign_advice_from_instance(
-                    || "enable output",
+        // [added: the one Wake constraint (WAKE-v1 §5). `rho_old` is the cell that fed
+        // NoteCommit and DeriveNullifier above, not a copy.]
+        if !self.skips(sab(SabName::Link)) {
+            match self.kind {
+                Kind::Hop => layouter.constrain_instance(rho_old.cell(), config.primary, LINK)?,
+                Kind::Genesis => layouter.constrain_instance(
+                    cm_old.extract_p().inner().cell(),
                     config.primary,
-                    ENABLE_OUTPUT,
-                    config.advices[7],
-                    0,
-                )?;
-
-                config.q_orchard.enable(&mut region, 0)
-            },
-        )?;
+                    LINK,
+                )?,
+            }
+        }
 
-        Ok(AddressPoints {
-            g_d_old,
-            pk_d_old,
-            g_d_new,
-            pk_d_new,
-        })
+        Ok(())
     }
```
