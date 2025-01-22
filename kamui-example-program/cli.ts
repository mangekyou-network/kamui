import * as anchor from '@project-serum/anchor';
import { AnchorProvider, BN } from '@project-serum/anchor';
import NodeWallet from '@project-serum/anchor/dist/cjs/nodewallet';
import { clusterApiUrl, Keypair, LAMPORTS_PER_SOL, SystemProgram, SYSVAR_RECENT_BLOCKHASHES_PUBKEY } from '@solana/web3.js';

import { AnchorUsingVrf, IDL } from './target/types/anchor_using_vrf';

const DEFAULT_COMMITMENT = 'confirmed';
const PROGRAM_ID = '3gfec8ANuaWzkNhAR5QRjUvGqUjMYLJ3YnSVhgMkugqv';

const OWNER_KEYPAIR = Keypair.fromSecretKey(new Uint8Array([
	136, 226, 76, 65, 7, 20, 124, 252, 73, 106, 66, 109, 104, 240, 81, 246, 2,
	142, 124, 38, 252, 34, 2, 185, 110, 179, 130, 144, 219, 147, 72, 105, 179,
	63, 58, 2, 124, 114, 96, 97, 215, 128, 189, 66, 206, 51, 177, 167, 22, 208,
	21, 153, 119, 14, 158, 7, 244, 62, 195, 134, 68, 188, 145, 226
]));

const USER_KEYPAIR = Keypair.fromSecretKey(new Uint8Array([
	227, 104, 46, 112, 139, 49, 32, 30, 151, 48, 74, 166, 69, 251, 31, 69, 114,
	187, 185, 171, 65, 83, 195, 82, 146, 84, 115, 121, 34, 202, 115, 217, 239,
	238, 7, 113, 126, 75, 59, 55, 161, 15, 237, 112, 92, 240, 69, 153, 231, 130,
	104, 13, 12, 92, 67, 182, 181, 117, 61, 100, 205, 172, 54, 150
]));

const sleep = (time: number) => new Promise(resolve => setTimeout(resolve, time));

(async function() {
	const url = clusterApiUrl('devnet');
	const provider = new AnchorProvider(
		new anchor.web3.Connection(url, { commitment: DEFAULT_COMMITMENT }),
		new NodeWallet(OWNER_KEYPAIR),
		{ commitment: DEFAULT_COMMITMENT }
	);

	anchor.setProvider(provider);

	const client: anchor.Program<AnchorUsingVrf> = new anchor.Program(
		IDL,
		PROGRAM_ID,
		provider,
		new anchor.BorshCoder(IDL),
	);

	const [statePubkey, stateBump] = anchor.utils.publicKey.findProgramAddressSync(
		[
			Buffer.from('program_state')
		],
		client.programId
	);

	switch (process.argv[2]) {
		case 'airdrop': {
			await provider.connection.requestAirdrop(OWNER_KEYPAIR.publicKey, 1 * LAMPORTS_PER_SOL);
			await sleep(2000);

			const ownerBalance = await provider.connection.getBalance(OWNER_KEYPAIR.publicKey);
			console.log('Owner balance: ', ownerBalance / LAMPORTS_PER_SOL);

			await sleep(10000);

			await provider.connection.requestAirdrop(USER_KEYPAIR.publicKey, 1 * LAMPORTS_PER_SOL);
			await sleep(2000);
			const userBalance = await provider.connection.getBalance(USER_KEYPAIR.publicKey);
			console.log('User balance: ', userBalance / LAMPORTS_PER_SOL);

			break;
		}
		case 'init': {
			const tx = await client.methods
				.init()
				.accounts({
					owner: OWNER_KEYPAIR.publicKey,
					state: statePubkey,
					systemProgram: SystemProgram.programId,
				})
				.signers([OWNER_KEYPAIR])
				.rpc({ commitment: DEFAULT_COMMITMENT });

			console.log(tx);
			const trans = await provider.connection.getTransaction(tx, { commitment: DEFAULT_COMMITMENT });
			console.log(trans.meta.logMessages);

			break;
		}
		case 'play': {
			const programState = await client.account.programState.fetch(statePubkey);
			const [vrfPubkey, vrfBump] = anchor.utils.publicKey.findProgramAddressSync(
				[
					Buffer.from('vrf', 'utf-8'),
					USER_KEYPAIR.publicKey.toBuffer(),
					programState.round.toBuffer('be', 8),
				],
				client.programId,
			);

			const tx = await client.methods
				.flipACoin(new BN(10))
				.accounts({
					user: USER_KEYPAIR.publicKey,
					state: statePubkey,
					vrf: vrfPubkey,
					systemProgram: SystemProgram.programId,
					recentSlothashes: SYSVAR_RECENT_BLOCKHASHES_PUBKEY,
				})
				.signers([ USER_KEYPAIR ])
				.rpc({ commitment: DEFAULT_COMMITMENT });

			const trans = await provider.connection.getTransaction(tx, { commitment: DEFAULT_COMMITMENT });
			console.log(trans.meta.logMessages);
			break;
		}
		default:
			console.log('unknown command', process.argv);
			break;
	};
})();
